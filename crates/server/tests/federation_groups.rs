//! Federation group mappings: upstream claim values keep local group
//! memberships on every sign-in, without touching manual ones; repoints,
//! unlinks, deleted mappings and deleted providers drop what they kept.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::{Method, StatusCode};
use common::{
    federation::{Fed, IDPS},
    groups::{add_manually, group, map, mapped, memberships, sign_in_with, sorted},
    mgmt::{audited, audited_any},
};
use entity::{user_identities, users};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Value, json};
use uuid::Uuid;

/// The `group.member_remove` events of `group` that a federation path wrote.
async fn mapped_removals(fed: &Fed, group: Uuid) -> Vec<Value> {
    audited(&fed.f.db, "group.member_remove", group)
        .await
        .into_iter()
        .filter(|e| e["via"] == "federation")
        .collect()
}

#[tokio::test]
async fn sign_ins_keep_mapped_memberships_only() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let (eng, ops, both, manual) = (
        group(&fed, "Eng").await,
        group(&fed, "Ops").await,
        group(&fed, "Both").await,
        group(&fed, "Manual").await,
    );
    mapped(&fed, &idp, "groups", "eng", eng).await;
    mapped(&fed, &idp, "groups", "dev", eng).await;
    mapped(&fed, &idp, "roles", "ops", ops).await;
    mapped(&fed, &idp, "groups", "x", both).await;
    // JIT applies them; values are matched exactly, any claim shape.
    let claims = json!({ "groups": ["eng", "dev", "x", "Ops"], "roles": "ops" });
    let user = sign_in_with(&fed, &idp, claims).await;
    assert_eq!(
        memberships(&fed, user.id).await,
        sorted(vec![
            (eng, false, true),
            (ops, false, true),
            (both, false, true)
        ])
    );
    let added = audited(&fed.f.db, "group.member_add", eng).await;
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["via"], "federation");
    assert_eq!(added[0]["idp_id"], json!(idp));
    // Manual: a mapped membership becomes manual too, a second add is 409.
    assert_eq!(
        add_manually(&fed, both, user.id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        add_manually(&fed, both, user.id).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        add_manually(&fed, manual, user.id).await,
        StatusCode::NO_CONTENT
    );
    // Values gone: only what nothing but the mapping kept goes.
    let user = sign_in_with(&fed, &idp, json!({ "groups": "eng" })).await;
    assert_eq!(
        memberships(&fed, user.id).await,
        sorted(vec![
            (eng, false, true),
            (both, true, false),
            (manual, true, false)
        ])
    );
    let removed = audited(&fed.f.db, "group.member_remove", ops).await;
    assert_eq!(removed[0]["user_id"], json!(user.id));
    assert!(
        audited(&fed.f.db, "group.member_remove", both)
            .await
            .is_empty()
    );
    // No claim at all: every mapped membership goes, manual ones stay.
    let user = sign_in_with(&fed, &idp, json!({})).await;
    assert_eq!(
        memberships(&fed, user.id).await,
        sorted(vec![(both, true, false), (manual, true, false)])
    );
    // A membership of the user that existed before the mapping isn't taken over.
    sign_in_with(&fed, &idp, json!({ "groups": "x" })).await;
    sign_in_with(&fed, &idp, json!({})).await;
    assert!(
        memberships(&fed, user.id)
            .await
            .contains(&(both, true, false))
    );
}

#[tokio::test]
async fn mapping_api_validates_and_cleans_up() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let (eng, admins) = (group(&fed, "Eng").await, group(&fed, "Admins").await);
    let (status, _) = map(&fed, &idp, "bad claim", "v", eng).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = map(&fed, &idp, "groups", "", eng).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = map(&fed, &idp, "groups", "v", Uuid::now_v7()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = map(&fed, &Uuid::now_v7().to_string(), "groups", "v", eng).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let first = mapped(&fed, &idp, "groups", "eng", eng).await;
    let (status, _) = map(&fed, &idp, "groups", "eng", eng).await;
    assert_eq!(status, StatusCode::CONFLICT);
    mapped(&fed, &idp, "roles", "eng", eng).await;
    mapped(&fed, &idp, "roles", "admin", admins).await;
    let (status, list) = fed
        .api(Method::GET, &format!("{IDPS}/{idp}/group-mappings"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["items"].as_array().unwrap().len(), 3);
    assert_eq!(list["items"][0]["group_display_name"], "Eng");
    let user = sign_in_with(&fed, &idp, json!({ "groups": ["eng"], "roles": ["admin"] })).await;
    assert_eq!(memberships(&fed, user.id).await.len(), 2);
    let delete = |id: &str| format!("{IDPS}/{idp}/group-mappings/{id}");
    // Another mapping still grants Eng: the membership stays for now.
    assert_eq!(
        fed.api(Method::DELETE, &delete(&first), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(memberships(&fed, user.id).await.len(), 2);
    assert_eq!(
        fed.api(Method::DELETE, &delete(&first), None).await.0,
        StatusCode::NOT_FOUND
    );
    // The last mapping of Admins goes, and so does the membership.
    let admin_mapping = list["items"][2]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        fed.api(Method::DELETE, &delete(&admin_mapping), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(memberships(&fed, user.id).await, vec![(eng, false, true)]);
    let idp_id = Uuid::parse_str(&idp).unwrap();
    let events = audited(&fed.f.db, "identity_provider.group_mapping_remove", idp_id).await;
    assert_eq!(events[1]["memberships_removed"], 1);
    let removed = mapped_removals(&fed, admins).await;
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["user_id"], json!(user.id));
    assert_eq!(removed[0]["idp_id"], json!(idp_id));
    assert!(mapped_removals(&fed, eng).await.is_empty());
    assert_eq!(events[0]["memberships_removed"], 0);
    let events = audited(&fed.f.db, "identity_provider.group_mapping_add", idp_id).await;
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["group_display_name"], "Eng");
}

#[tokio::test]
async fn repoint_unlink_and_delete_drop_mapped_memberships() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let (eng, ops) = (group(&fed, "Eng").await, group(&fed, "Ops").await);
    mapped(&fed, &idp, "groups", "eng", eng).await;
    mapped(&fed, &idp, "groups", "ops", ops).await;
    let claims = json!({ "groups": ["eng", "ops"] });
    let user = sign_in_with(&fed, &idp, claims.clone()).await;
    add_manually(&fed, ops, user.id).await;
    // Repoint: the mapping-only membership goes, the manual one stays.
    fed.patch_idp(&idp, json!({ "client_id": "other-rp" }))
        .await;
    assert_eq!(memberships(&fed, user.id).await, vec![(ops, true, false)]);
    let events = audited_any(&fed.f.db, "identity_provider.update").await;
    assert_eq!(events.last().unwrap()["memberships_removed"], 1);
    // Each membership removed is audited by itself; an unmarked one isn't.
    let removed = mapped_removals(&fed, eng).await;
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["user_id"], json!(user.id));
    assert_eq!(removed[0]["idp_id"], json!(idp));
    assert!(mapped_removals(&fed, ops).await.is_empty());
    fed.patch_idp(&idp, json!({ "client_id": common::upstream::CLIENT_ID }))
        .await;
    // Unlink (the user has a password, so the identity isn't the last way in).
    let user = {
        // Relinking by sign-in is refused (account_exists); link the row directly.
        let link = user_identities::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(fed.f.tenant.id),
            user_id: Set(user.id),
            idp_id: Set(Uuid::parse_str(&idp).unwrap()),
            subject: Set("upstream-sub-1".into()),
            email: Set(None),
            linked_at: Set(chrono::Utc::now().fixed_offset()),
            last_used_at: Set(None),
        };
        link.insert(&fed.f.db).await.unwrap();
        sign_in_with(&fed, &idp, claims.clone()).await
    };
    assert_eq!(
        memberships(&fed, user.id).await,
        sorted(vec![(eng, false, true), (ops, true, false)])
    );
    let mut row: users::ActiveModel = user.clone().into();
    row.password_hash = Set(Some("$argon2id$placeholder".into()));
    row.update(&fed.f.db).await.unwrap();
    let identity = user_identities::Entity::find()
        .filter(user_identities::Column::UserId.eq(user.id))
        .one(&fed.f.db)
        .await
        .unwrap()
        .unwrap();
    let path = format!("/api/v1/users/{}/identities/{}", user.id, identity.id);
    let (status, out) = fed.api(Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{out}");
    assert_eq!(memberships(&fed, user.id).await, vec![(ops, true, false)]);
    let events = audited(&fed.f.db, "user.identity_unlink", user.id).await;
    assert_eq!(events[0]["memberships_removed"], 1);
    assert_eq!(mapped_removals(&fed, eng).await.len(), 2);
    // Deleting the provider: same, and the manual row survives the FK.
    let link = user_identities::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(fed.f.tenant.id),
        user_id: Set(user.id),
        idp_id: Set(Uuid::parse_str(&idp).unwrap()),
        subject: Set("upstream-sub-1".into()),
        email: Set(None),
        linked_at: Set(chrono::Utc::now().fixed_offset()),
        last_used_at: Set(None),
    };
    link.insert(&fed.f.db).await.unwrap();
    // Ops removed by hand, re-added by the mapping, then manual as well.
    let member = format!("/api/v1/groups/{ops}/members/{}", user.id);
    assert_eq!(
        fed.api(Method::DELETE, &member, None).await.0,
        StatusCode::NO_CONTENT
    );
    sign_in_with(&fed, &idp, claims).await;
    assert_eq!(
        add_manually(&fed, ops, user.id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        memberships(&fed, user.id).await,
        sorted(vec![(eng, false, true), (ops, true, true)])
    );
    let (status, _) = fed
        .api(Method::DELETE, &format!("{IDPS}/{idp}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(memberships(&fed, user.id).await, vec![(ops, true, false)]);
    let events = audited_any(&fed.f.db, "identity_provider.delete").await;
    assert_eq!(events[0]["memberships_removed"], 1);
    let removed = mapped_removals(&fed, eng).await;
    assert_eq!(removed.len(), 3);
    assert_eq!(removed[2]["user_id"], json!(user.id));
    assert!(mapped_removals(&fed, ops).await.is_empty());
}
