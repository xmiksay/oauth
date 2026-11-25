//! Up-front check, before the first write, that the file doesn't refer to
//! an object it deletes: references resolve against the database, so a
//! membership, assignment, permission or consent naming a managed user,
//! group or app the file no longer declares would be created and then
//! cascade away with its target in the same run.

use std::collections::{BTreeSet, HashSet};

use anyhow::bail;
use entity::applications;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    sea_query::{Expr, Func},
};

use super::{ctx::Ctx, spec::Spec};
use crate::directory;

fn fold(name: &str) -> String {
    name.trim().to_lowercase()
}

fn deleted(what: &str, name: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "the file references {what} `{name}`, which this file deletes \
         (it is managed by apply but no longer declared): declare it or drop the reference"
    )
}

/// The names `spec` refers to (beyond the objects it declares), by kind.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Refs<'a> {
    pub users: BTreeSet<&'a str>,
    pub groups: BTreeSet<&'a str>,
    pub apps: BTreeSet<&'a str>,
}

fn user_refs(spec: &Spec) -> impl Iterator<Item = &str> {
    spec.groups
        .iter()
        .flat_map(|g| g.members.iter())
        .chain(spec.directory_roles.iter().map(|d| &d.user))
        .chain(spec.role_assignments.iter().filter_map(|a| a.user.as_ref()))
        .map(String::as_str)
}

fn group_refs(spec: &Spec) -> impl Iterator<Item = &str> {
    spec.role_assignments
        .iter()
        .filter_map(|a| a.group.as_deref())
}

/// User and group names `principals` returns.
pub struct Principals<'a> {
    pub users: BTreeSet<&'a str>,
    pub groups: BTreeSet<&'a str>,
}

/// The users and groups apply may insert rows pointing at (memberships,
/// directory roles, role assignments), declared or not, plus every group it
/// declares. An existing one that apply leaves unchanged is never written
/// before those inserts, so their FK check would be its first lock on it
/// (`provision::run`).
pub fn principals(spec: &Spec) -> Principals<'_> {
    let declared = spec.groups.iter().map(|g| g.display_name.as_str());
    Principals {
        users: user_refs(spec).collect(),
        groups: group_refs(spec).chain(declared).collect(),
    }
}

/// `names` as the lookups match them: trimmed, then lowercased by Postgres
/// (`lower($1)`, as `find_user_by_email` / `Ctx::find_group` do; Rust's
/// `to_lowercase` disagrees with it on e.g. `İ` or a final sigma, so a
/// name lowercased in Rust could resolve in the lookup yet never be
/// locked). Drops the names that can't be stored (Postgres rejects NUL in
/// a parameter).
pub fn lowered(names: &BTreeSet<&str>) -> Vec<Expr> {
    names
        .iter()
        .filter(|n| !n.chars().any(char::is_control))
        .map(|n| Func::lower(Expr::val(n.trim())).into())
        .collect()
}

/// References to users, groups and apps the file doesn't declare itself.
pub fn undeclared(spec: &Spec) -> Refs<'_> {
    let users: HashSet<String> = spec.users.iter().map(|u| fold(&u.email)).collect();
    let groups: HashSet<String> = spec.groups.iter().map(|g| fold(&g.display_name)).collect();
    let apps: HashSet<&str> = spec
        .applications
        .iter()
        .map(|a| a.client_id.as_str())
        .collect();
    let client_ids = spec
        .applications
        .iter()
        .flat_map(|a| a.required_permissions.iter().map(|p| p.resource.as_str()))
        .chain(
            spec.role_assignments
                .iter()
                .flat_map(|a| std::iter::once(a.resource.as_str()).chain(a.application.as_deref())),
        )
        .chain(
            spec.admin_consents
                .iter()
                .flat_map(|c| [c.client.as_str(), c.resource.as_str()]),
        );
    Refs {
        users: user_refs(spec)
            .filter(|e| !users.contains(&fold(e)))
            .collect(),
        groups: group_refs(spec)
            .filter(|g| !groups.contains(&fold(g)))
            .collect(),
        apps: client_ids.filter(|c| !apps.contains(c)).collect(),
    }
}

pub async fn check(conn: &impl ConnectionTrait, cx: &Ctx, spec: &Spec) -> anyhow::Result<()> {
    let refs = undeclared(spec);
    for email in refs.users {
        let found = directory::find_user_by_email(conn, cx.tenant_id, email.trim()).await?;
        if found.is_some_and(|u| u.managed) {
            bail!(deleted("user", email));
        }
    }
    for name in refs.groups {
        if cx.find_group(conn, name).await?.is_some_and(|g| g.managed) {
            bail!(deleted("group", name));
        }
    }
    for client_id in refs.apps {
        let found = applications::Entity::find()
            .filter(applications::Column::TenantId.eq(cx.tenant_id))
            .filter(applications::Column::ClientId.eq(client_id))
            .one(conn)
            .await?;
        if found.is_some_and(|a| a.managed) {
            bail!(deleted("application", client_id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::sea_query::{Alias, ExprTrait, PostgresQueryBuilder, Query};

    use super::*;
    use crate::provision::parse;

    #[test]
    fn only_undeclared_names_are_checked() {
        let spec = parse(
            r"
tenant: t
users: [{ email: Alice@example.com, display_name: A }]
groups: [{ display_name: Eng, members: [alice@example.com, bob@example.com] }]
applications:
  - client_id: web
    display_name: Web
    required_permissions: [{ resource: api, type: delegated, value: X }]
directory_roles: [{ user: carol@example.com, role: UserAdmin }]
role_assignments:
  - { resource: web, role: R, group: eng }
  - { resource: api, role: R, group: Ops }
  - { resource: api, role: R, application: sync }
admin_consents: [{ client: web, resource: api }]
",
        )
        .unwrap();
        let refs = undeclared(&spec);
        assert_eq!(
            refs.users.into_iter().collect::<Vec<_>>(),
            ["bob@example.com", "carol@example.com"]
        );
        assert_eq!(refs.groups.into_iter().collect::<Vec<_>>(), ["Ops"]);
        assert_eq!(refs.apps.into_iter().collect::<Vec<_>>(), ["api", "sync"]);
        let all = principals(&spec);
        assert_eq!(
            all.users.into_iter().collect::<Vec<_>>(),
            ["alice@example.com", "bob@example.com", "carol@example.com"]
        );
        assert_eq!(
            all.groups.into_iter().collect::<Vec<_>>(),
            ["Eng", "Ops", "eng"]
        );
    }

    #[test]
    fn names_are_lowered_by_postgres_like_lookups() {
        let names = BTreeSet::from([" Ann@Example.com", "ΟΜΑΣ", "bad\0@x", "b@x"]);
        let lowered = lowered(&names);
        assert_eq!(lowered.len(), 3);
        let mut sql = Query::select();
        sql.expr(Expr::expr(Expr::col(Alias::new("c"))).is_in(lowered));
        assert_eq!(
            sql.to_string(PostgresQueryBuilder),
            r#"SELECT "c" IN (LOWER('Ann@Example.com'), LOWER('b@x'), LOWER('ΟΜΑΣ'))"#
        );
    }
}
