//! Federation group mappings, continued: who may manage them, tenant
//! isolation, the per-provider cap, two providers mapping one group, and
//! the `link` stage applying them (with mappings changed while parked).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::{Method, StatusCode};
use common::{
    at,
    browser::Browser,
    federation::{Fed, IDPS, is_login_page},
    flow::PASSWORD,
    groups::{group, map, mapped, memberships, sign_in_with, uuid},
    mgmt::{audited, call, mint_user_token, user_with_roles},
    upstream::Account,
};
use entity::{
    enums::DirectoryRole::{GlobalAdmin, UserAdmin},
    group_members, idp_group_mappings, user_identities,
};
use oauth_server::directory::{self, NewTenant};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};
use serde_json::json;
use uuid::Uuid;

fn mappings_of(idp: &str) -> String {
    format!("{IDPS}/{idp}/group-mappings")
}

#[tokio::test]
async fn only_a_global_admin_writes_mappings() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let eng = group(&fed, "Eng").await;
    let id = mapped(&fed, &idp, "groups", "eng", eng).await;
    let admin = user_with_roles(&fed.f.db, fed.f.tenant.id, "ua@example.com", &[UserAdmin]).await;
    let token = mint_user_token(&fed.f.db, &fed.f.config, &fed.f.tenant, &admin).await;
    let as_ua = |method, path: String, body| {
        let token = token.clone();
        let app = fed.f.app.clone();
        async move { call(&app, method, &path, Some(&token), body).await }
    };
    let (status, list) = as_ua(Method::GET, mappings_of(&idp), None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    let body = json!({ "claim": "groups", "value": "ops", "group_id": eng });
    let (status, _) = as_ua(Method::POST, mappings_of(&idp), Some(&body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let one = format!("{}/{id}", mappings_of(&idp));
    let (status, _) = as_ua(Method::DELETE, one, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, list) = fed.api(Method::GET, &mappings_of(&idp), None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn mappings_are_tenant_scoped_and_capped() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let eng = group(&fed, "Eng").await;
    let ours = mapped(&fed, &idp, "groups", "eng", eng).await;
    let other = directory::create_tenant(
        &fed.f.db,
        &fed.f.config,
        NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let ga = user_with_roles(&fed.f.db, other.id, "ga@fabrikam.example", &[GlobalAdmin]).await;
    let token = mint_user_token(&fed.f.db, &fed.f.config, &other, &ga).await;
    let theirs = |method, path: &str, body: Option<serde_json::Value>| {
        let (app, token, url) = (fed.f.app.clone(), token.clone(), at("fabrikam", path));
        async move { call(&app, method, &url, Some(&token), body.as_ref()).await }
    };
    let (status, out) = theirs(Method::POST, IDPS, Some(fed.body(json!({})))).await;
    assert_eq!(status, StatusCode::CREATED, "{out}");
    let their_idp = out["id"].as_str().unwrap().to_owned();
    let body = json!({ "display_name": "Theirs" });
    let (_, out) = theirs(Method::POST, "/api/v1/groups", Some(body)).await;
    let their_group = uuid(&out["id"]);
    let body = json!({ "claim": "groups", "value": "x", "group_id": their_group });
    let (status, out) = theirs(Method::POST, &mappings_of(&their_idp), Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{out}");
    let their_mapping = out["id"].as_str().unwrap().to_owned();
    // Their provider, their mapping, their group: unknown here.
    let (status, _) = fed.api(Method::GET, &mappings_of(&their_idp), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = map(&fed, &their_idp, "groups", "y", eng).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let path = format!("{}/{their_mapping}", mappings_of(&idp));
    assert_eq!(
        fed.api(Method::DELETE, &path, None).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, _) = map(&fed, &idp, "groups", "y", their_group).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Nor ours there.
    let path = format!("{}/{ours}", mappings_of(&their_idp));
    assert_eq!(
        theirs(Method::DELETE, &path, None).await.0,
        StatusCode::NOT_FOUND
    );
    // 100 per provider: 99 more fit, the 101st is a conflict.
    for i in 0..99 {
        let row = idp_group_mappings::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(fed.f.tenant.id),
            idp_id: Set(Uuid::parse_str(&idp).unwrap()),
            claim: Set("groups".into()),
            value: Set(format!("v{i}")),
            group_id: Set(eng),
            created_at: Set(chrono::Utc::now().fixed_offset()),
        };
        row.insert(&fed.f.db).await.unwrap();
    }
    let (status, _) = map(&fed, &idp, "groups", "one-more", eng).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn providers_mapping_one_group_leave_each_others_memberships() {
    let fed = Fed::new().await;
    let (a, b) = (
        fed.idp(json!({})).await,
        fed.idp(json!({ "name": "Other" })).await,
    );
    let eng = group(&fed, "Eng").await;
    mapped(&fed, &a, "groups", "eng", eng).await;
    mapped(&fed, &b, "groups", "eng", eng).await;
    let user = sign_in_with(&fed, &a, json!({ "groups": "eng" })).await;
    let link = user_identities::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(fed.f.tenant.id),
        user_id: Set(user.id),
        idp_id: Set(Uuid::parse_str(&b).unwrap()),
        subject: Set("upstream-sub-1".into()),
        email: Set(None),
        linked_at: Set(chrono::Utc::now().fixed_offset()),
        last_used_at: Set(None),
    };
    link.insert(&fed.f.db).await.unwrap();
    let owner = || async {
        let row = group_members::Entity::find_by_id((eng, user.id))
            .one(&fed.f.db)
            .await
            .unwrap();
        row.map(|m| m.idp_id.map(|i| i.to_string()))
    };
    // B neither takes over nor removes what A keeps.
    sign_in_with(&fed, &b, json!({})).await;
    assert_eq!(owner().await, Some(Some(a.clone())));
    sign_in_with(&fed, &b, json!({ "groups": "eng" })).await;
    assert_eq!(owner().await, Some(Some(a.clone())));
    // A lets go; B's next sign-in keeps it on its own account.
    sign_in_with(&fed, &a, json!({})).await;
    assert_eq!(owner().await, None);
    sign_in_with(&fed, &b, json!({ "groups": "eng" })).await;
    assert_eq!(owner().await, Some(Some(b.clone())));
    sign_in_with(&fed, &a, json!({})).await;
    assert_eq!(owner().await, Some(Some(b)));
}

async fn parked(fed: &Fed, browser: &mut Browser, idp: &str) -> String {
    let tx = fed.authorize(browser, &[]).await;
    let url = fed.begin(browser, &tx, idp).await;
    let location = fed.come_back(browser, &url).await;
    assert!(is_login_page(&location, &tx), "{location}");
    tx
}

#[tokio::test]
async fn the_link_stage_applies_mappings_read_when_verified() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({ "policy": "link_only" })).await;
    let (eng, dev) = (group(&fed, "Eng").await, group(&fed, "Dev").await);
    mapped(&fed, &idp, "groups", "dev", dev).await;
    let old = mapped(&fed, &idp, "groups", "eng", eng).await;
    let ann = fed.f.user.id;
    // Ann holds Eng through the mapping (as an earlier link would leave her).
    let row = group_members::ActiveModel {
        tenant_id: Set(fed.f.tenant.id),
        group_id: Set(eng),
        user_id: Set(ann),
        manual: Set(false),
        idp_id: Set(Some(Uuid::parse_str(&idp).unwrap())),
        ..Default::default()
    };
    row.insert(&fed.f.db).await.unwrap();
    let mut account = Account::new("upstream-sub-1", "pat@upstream.example");
    account.extra = json!({ "groups": ["dev"], "roles": ["eng"] });
    fed.up.set_account(account);
    let mut browser = fed.f.browser();
    let tx = parked(&fed, &mut browser, &idp).await;
    // While parked Eng moves to a claim the token wasn't read for.
    mapped(&fed, &idp, "roles", "eng", eng).await;
    let path = format!("{}/{old}", mappings_of(&idp));
    assert_eq!(
        fed.api(Method::DELETE, &path, None).await.0,
        StatusCode::NO_CONTENT
    );
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (status, resp) = browser.step(&tx, "password", body).await;
    assert!(resp["redirect"].is_string(), "{status} {resp}");
    // Dev from the claim it was verified with; Eng left for the next sign-in.
    let rows = memberships(&fed, ann).await;
    assert!(rows.contains(&(dev, false, true)), "{rows:?}");
    assert!(rows.contains(&(eng, false, true)), "{rows:?}");
    // The member list says where each membership comes from.
    let (_, list) = fed
        .api(Method::GET, &format!("/api/v1/groups/{eng}/members"), None)
        .await;
    assert_eq!(list["items"][0]["id"], json!(ann));
    assert_eq!(list["items"][0]["manual"], false);
    assert_eq!(list["items"][0]["idp_id"], json!(idp));
    let path = format!("/api/v1/groups/{}/members", fed.f.group);
    let (_, list) = fed.api(Method::GET, &path, None).await;
    assert_eq!(list["items"][0]["manual"], true);
    assert!(list["items"][0]["idp_id"].is_null());
    let added = audited(&fed.f.db, "group.member_add", dev).await;
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["user_id"], json!(ann));
    assert!(
        audited(&fed.f.db, "group.member_remove", eng)
            .await
            .is_empty()
    );
}
