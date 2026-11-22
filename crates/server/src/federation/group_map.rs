//! Group mappings of an identity provider: an upstream claim value puts
//! the signed-in user into a local group. A membership a provider's
//! mappings created carries its `idp_id`; a sign-in through that provider
//! adds and removes only such rows, so manual memberships (and those of
//! other providers) are never touched. A row both manual and mapped loses
//! only the mapping mark when the claim value goes.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use anyhow::Context;
use entity::{enums::Outcome, group_members, idp_group_mappings};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, sea_query::Expr,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::profile;
use crate::audit::{self, EventType};

/// Values read from one claim; Entra, for one, caps its `groups` claim at
/// 200 entries, anything beyond this is ignored.
pub const MAX_CLAIM_VALUES: usize = 256;
/// Mappings per identity provider.
pub const MAX_MAPPINGS: u64 = 100;

/// Upstream claim name → its string values.
pub type ClaimValues = BTreeMap<String, BTreeSet<String>>;

/// The values of `names` in a verified token's `claims`: a string or an
/// array of strings, at most [`MAX_CLAIM_VALUES`] entries, each 1–256 bytes
/// without control characters (others are skipped).
pub fn extract(claims: &Map<String, Value>, names: &[String]) -> ClaimValues {
    let mut out = ClaimValues::new();
    for name in names {
        let values: BTreeSet<String> = match claims.get(name) {
            Some(Value::String(v)) => profile::clean_token(v).into_iter().collect(),
            Some(Value::Array(list)) => list
                .iter()
                .take(MAX_CLAIM_VALUES)
                .filter_map(Value::as_str)
                .filter_map(profile::clean_token)
                .collect(),
            _ => continue,
        };
        if !values.is_empty() {
            out.insert(name.clone(), values);
        }
    }
    out
}

/// The groups `mappings` grant for `values`.
pub fn wanted(mappings: &[idp_group_mappings::Model], values: &ClaimValues) -> BTreeSet<Uuid> {
    mappings
        .iter()
        .filter(|m| values.get(&m.claim).is_some_and(|v| v.contains(&m.value)))
        .map(|m| m.group_id)
        .collect()
}

pub async fn list(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> anyhow::Result<Vec<idp_group_mappings::Model>> {
    idp_group_mappings::Entity::find()
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id))
        .order_by_asc(idp_group_mappings::Column::Id)
        .all(conn)
        .await
        .context("loading group mappings")
}

/// The claim names the provider's mappings read (what the ID token check
/// keeps).
pub async fn claim_names(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> anyhow::Result<Vec<String>> {
    idp_group_mappings::Entity::find()
        .select_only()
        .column(idp_group_mappings::Column::Claim)
        .distinct()
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id))
        .into_tuple()
        .all(conn)
        .await
        .context("loading mapped claim names")
}

/// Memberships a sync added and removed (group ids).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<Uuid>,
    pub removed: Vec<Uuid>,
}

/// [`apply`], one audit event (`group.member_add` / `_remove`, actor the
/// user) per membership changed.
pub async fn sync(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Uuid,
    ip: Option<IpAddr>,
    values: &ClaimValues,
) -> anyhow::Result<Changes> {
    let changes = apply(conn, tenant_id, idp_id, user_id, values).await?;
    let added = changes
        .added
        .iter()
        .map(|g| (*g, EventType::GroupMemberAdd));
    let removed = changes
        .removed
        .iter()
        .map(|g| (*g, EventType::GroupMemberRemove));
    for (group_id, event_type) in added.chain(removed) {
        let event = audit::Event {
            tenant_id,
            actor: audit::Actor::User(Some(user_id)),
            event_type,
            target: Some(audit::Target::Group(group_id)),
            outcome: Outcome::Success,
            ip,
            details: json!({ "user_id": user_id, "via": "federation", "idp_id": idp_id }),
        };
        audit::record(conn, event).await?;
    }
    Ok(changes)
}

/// Brings `user_id`'s memberships owned by `idp_id` in line with `values`.
/// Run in the sign-in transaction, after `idps::lock_current`: mapping
/// writes lock the provider `FOR UPDATE`, so the mappings read here stay
/// the current ones until it commits.
pub async fn apply(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Uuid,
    values: &ClaimValues,
) -> anyhow::Result<Changes> {
    let wanted = wanted(&list(conn, tenant_id, idp_id).await?, values);
    let owned = group_members::Entity::find()
        .filter(group_members::Column::TenantId.eq(tenant_id))
        .filter(group_members::Column::UserId.eq(user_id))
        .filter(group_members::Column::IdpId.eq(idp_id))
        .all(conn)
        .await
        .context("loading mapped memberships")?;
    let mut changes = Changes::default();
    for row in owned.iter().filter(|m| !wanted.contains(&m.group_id)) {
        let filter = sea_orm::Condition::all()
            .add(group_members::Column::TenantId.eq(tenant_id))
            .add(group_members::Column::GroupId.eq(row.group_id))
            .add(group_members::Column::UserId.eq(user_id))
            .add(group_members::Column::IdpId.eq(idp_id));
        if row.manual {
            unmark(conn, filter).await?;
        } else {
            let done = group_members::Entity::delete_many()
                .filter(filter.add(group_members::Column::Manual.eq(false)))
                .exec(conn)
                .await
                .context("removing a mapped membership")?;
            if done.rows_affected > 0 {
                changes.removed.push(row.group_id);
            }
        }
    }
    for group_id in wanted
        .iter()
        .filter(|g| !owned.iter().any(|m| m.group_id == **g))
    {
        let row = group_members::ActiveModel {
            tenant_id: Set(tenant_id),
            group_id: Set(*group_id),
            user_id: Set(user_id),
            manual: Set(false),
            idp_id: Set(Some(idp_id)),
            ..Default::default()
        };
        // An existing membership (manual, or another provider's) stays as
        // it is: it doesn't need this provider to exist.
        let inserted = group_members::Entity::insert(row)
            .on_conflict(
                sea_orm::sea_query::OnConflict::columns([
                    group_members::Column::GroupId,
                    group_members::Column::UserId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(conn)
            .await
            .context("adding a mapped membership")?;
        if inserted > 0 {
            changes.added.push(*group_id);
        }
    }
    Ok(changes)
}

async fn unmark(conn: &impl ConnectionTrait, filter: sea_orm::Condition) -> anyhow::Result<()> {
    group_members::Entity::update_many()
        .col_expr(
            group_members::Column::IdpId,
            Expr::value(Option::<Uuid>::None),
        )
        .filter(filter.add(group_members::Column::Manual.eq(true)))
        .exec(conn)
        .await
        .context("unmarking a mapped membership")?;
    Ok(())
}

/// Drops the memberships `idp_id`'s mappings keep — of one user (`Some`,
/// an unlinked identity) or of everyone (a repoint, a deleted provider) —
/// and, when `group_id` is given, only in that group (a deleted mapping).
/// Manual ones lose just the mark. Returns the memberships removed.
pub async fn drop_owned(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Option<Uuid>,
    group_id: Option<Uuid>,
) -> anyhow::Result<u64> {
    let mut filter = sea_orm::Condition::all()
        .add(group_members::Column::TenantId.eq(tenant_id))
        .add(group_members::Column::IdpId.eq(idp_id));
    if let Some(user_id) = user_id {
        filter = filter.add(group_members::Column::UserId.eq(user_id));
    }
    if let Some(group_id) = group_id {
        filter = filter.add(group_members::Column::GroupId.eq(group_id));
    }
    let removed = group_members::Entity::delete_many()
        .filter(filter.clone().add(group_members::Column::Manual.eq(false)))
        .exec(conn)
        .await
        .context("dropping mapped memberships")?;
    unmark(conn, filter).await?;
    Ok(removed.rows_affected)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn mapping(claim: &str, value: &str, group_id: Uuid) -> idp_group_mappings::Model {
        idp_group_mappings::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            idp_id: Uuid::nil(),
            claim: claim.into(),
            value: value.into(),
            group_id,
            created_at: chrono::Utc::now().fixed_offset(),
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn extract_bounds_values() {
        let many: Vec<String> = (0..300).map(|i| format!("g{i}")).collect();
        let claims = json!({
            "groups": ["a", "b", "a", 7, "", "x\u{0}", "y".repeat(257)],
            "roles": "admin",
            "big": many,
            "obj": {"a": 1},
            "unasked": ["z"],
        });
        let claims = claims.as_object().unwrap();
        let got = extract(
            claims,
            &names(&["groups", "roles", "big", "obj", "missing"]),
        );
        assert_eq!(got["groups"], BTreeSet::from(["a".into(), "b".into()]));
        assert_eq!(got["roles"], BTreeSet::from(["admin".into()]));
        assert_eq!(got["big"].len(), MAX_CLAIM_VALUES);
        assert!(!got.contains_key("obj"));
        assert!(!got.contains_key("missing"));
        assert!(!got.contains_key("unasked"));
    }

    #[test]
    fn wanted_matches_claim_and_value_exactly() {
        let (g1, g2, g3) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mappings = [
            mapping("groups", "eng", g1),
            mapping("roles", "eng", g2),
            mapping("groups", "Ops", g3),
            mapping("groups", "dev", g1),
        ];
        let claims = json!({ "groups": ["eng", "dev", "ops"] });
        let values = extract(claims.as_object().unwrap(), &names(&["groups", "roles"]));
        assert_eq!(wanted(&mappings, &values), BTreeSet::from([g1]));
        assert!(wanted(&mappings, &ClaimValues::new()).is_empty());
    }
}
