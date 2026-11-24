//! What every apply step shares: the tenant, the change log (the dry-run
//! diff) and the audit events, recorded as actor `apply`.

use std::{collections::HashSet, str::FromStr};

use anyhow::Context;
use entity::{applications, enums::Outcome, groups, users};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter,
    sea_query::{Expr, ExprTrait, Func, PostgresQueryBuilder, QueryBuilder},
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    audit::{self, Actor, EventType, Target},
    directory,
};

pub struct Ctx {
    pub tenant_id: Uuid,
    pub changes: Vec<String>,
    /// Ids of the rows the file declares: pruning deletes the managed rows
    /// not in here (ids, not names, so case folding can't mismatch).
    pub kept: HashSet<Uuid>,
    /// The identity providers [`super::idps::lock_all`] locked before any
    /// user: only these may be locked again later.
    pub locked_idps: HashSet<Uuid>,
}

impl Ctx {
    /// Logs a change that isn't audited (apply's own marker).
    pub fn note(&mut self, line: String) {
        self.changes.push(line);
    }

    /// Logs `line` (`+` create, `~` update, `-` delete) and audits it.
    pub async fn record(
        &mut self,
        conn: &impl ConnectionTrait,
        line: String,
        event_type: EventType,
        target: Option<Target>,
        details: Value,
    ) -> anyhow::Result<()> {
        self.changes.push(line);
        audit::record(
            conn,
            audit::Event {
                tenant_id: self.tenant_id,
                actor: Actor::Apply,
                event_type,
                target,
                outcome: Outcome::Success,
                ip: None,
                details,
            },
        )
        .await
    }

    pub async fn app(
        &self,
        conn: &impl ConnectionTrait,
        client_id: &str,
    ) -> anyhow::Result<applications::Model> {
        applications::Entity::find()
            .filter(applications::Column::TenantId.eq(self.tenant_id))
            .filter(applications::Column::ClientId.eq(client_id))
            .one(conn)
            .await
            .context("looking up application")?
            .with_context(|| format!("application `{client_id}` not found"))
    }

    pub async fn user(
        &self,
        conn: &impl ConnectionTrait,
        email: &str,
    ) -> anyhow::Result<users::Model> {
        directory::find_user_by_email(conn, self.tenant_id, email.trim())
            .await?
            .with_context(|| format!("user `{email}` not found"))
    }

    /// Group names are unique ignoring letter case.
    pub async fn find_group(
        &self,
        conn: &impl ConnectionTrait,
        name: &str,
    ) -> anyhow::Result<Option<groups::Model>> {
        groups::Entity::find()
            .filter(groups::Column::TenantId.eq(self.tenant_id))
            .filter(
                Expr::expr(Func::lower(Expr::col(groups::Column::DisplayName)))
                    .eq(Func::lower(Expr::val(name.trim()))),
            )
            .one(conn)
            .await
            .context("looking up group")
    }

    pub async fn group(
        &self,
        conn: &impl ConnectionTrait,
        name: &str,
    ) -> anyhow::Result<groups::Model> {
        self.find_group(conn, name)
            .await?
            .with_context(|| format!("group `{name}` not found"))
    }
}

/// `field: old -> new` for each changed field that is a column of `M`.
/// A field that isn't one (the IdP's write-only `client_secret`, sealed in
/// another column) shows as `field: set`, so no secret ever reaches the
/// diff; callers only pass fields of the management API's bodies.
pub fn diff<M>(old: &M, new: &M, fields: &[&str]) -> Vec<String>
where
    M: ModelTrait,
    <M::Entity as EntityTrait>::Column: FromStr,
{
    fields
        .iter()
        .map(
            |field| match <M::Entity as EntityTrait>::Column::from_str(field) {
                Ok(col) => format!(
                    "{field}: {} -> {}",
                    PostgresQueryBuilder.value_to_string(&old.get(col)),
                    PostgresQueryBuilder.value_to_string(&new.get(col)),
                ),
                Err(_) => format!("{field}: set"),
            },
        )
        .collect()
}

/// `~ label: a, b` (+ `adopted` when apply took over an existing row; a
/// marker-only change is noted but not audited).
pub fn update_line(label: &str, changes: &[String], adopted: bool) -> String {
    let mut parts = changes.to_vec();
    if adopted {
        parts.push("adopted".to_owned());
    }
    format!("~ {label}: {}", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn update_lines() {
        let two = strings(&["x: 1 -> 2", "y: set"]);
        assert_eq!(
            update_line("app a", &two, false),
            "~ app a: x: 1 -> 2, y: set"
        );
        assert_eq!(
            update_line("app a", &strings(&["x"]), true),
            "~ app a: x, adopted"
        );
        assert_eq!(update_line("app a", &[], true), "~ app a: adopted");
    }

    fn group(name: &str, description: Option<&str>) -> groups::Model {
        let now = chrono::Utc::now().fixed_offset();
        groups::Model {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            display_name: name.to_owned(),
            description: description.map(str::to_owned),
            managed: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn diffs_show_old_and_new_values() {
        let old = group("Ops", None);
        let new = group("Operations", Some("on call"));
        assert_eq!(
            diff(&old, &new, &["display_name", "description"]),
            strings(&[
                "display_name: 'Ops' -> 'Operations'",
                "description: NULL -> 'on call'",
            ])
        );
    }

    #[test]
    fn diffs_never_show_values_of_non_columns() {
        let g = group("Ops", None);
        assert_eq!(
            diff(&g, &g, &["client_secret"]),
            strings(&["client_secret: set"])
        );
    }
}
