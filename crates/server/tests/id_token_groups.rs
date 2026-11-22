// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Groups in the ID token and userinfo: the client app's `id_token_groups`
//! (none | all | assigned) in its `groups_claim_format`, with the overage
//! rule of access tokens.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_admin_token, call},
    seed::{add_role, assign_role},
};
use sea_orm::ConnectionTrait;
use serde_json::{Map, Value, json};
use uuid::Uuid;

const OPENID: &str = "openid offline_access";

async fn set_web(f: &Fixture, body: Value) {
    let token = app_admin_token(f).await;
    let path = format!("/api/v1/applications/{}", f.web.id);
    let (st, body) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

/// A group named `name`, with the fixture user as a member when `member`.
async fn add_group(f: &Fixture, name: &str, member: bool) -> Uuid {
    let id = Uuid::now_v7();
    let mut sql = format!(
        "INSERT INTO groups (id, tenant_id, display_name) VALUES ('{id}', '{t}', '{name}');",
        t = f.tenant.id
    );
    if member {
        sql += &format!(
            "INSERT INTO group_members (tenant_id, group_id, user_id) VALUES ('{t}', '{id}', '{u}');",
            t = f.tenant.id,
            u = f.user.id
        );
    }
    f.db.execute_unprepared(&sql).await.unwrap();
    id
}

async fn id_claims(f: &Fixture, tokens: &Value) -> Map<String, Value> {
    f.verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await
}

async fn userinfo(f: &Fixture, tokens: &Value) -> Value {
    let at = tokens["access_token"].as_str().unwrap();
    let (st, body) = call(&f.app, Method::GET, "/oauth2/userinfo", Some(at), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn none_is_the_default_even_with_the_groups_scope() {
    let f = Fixture::new().await;
    let (_, tokens) = f.web_tokens("openid groups", "ann@example.com").await;
    assert!(id_claims(&f, &tokens).await.get("groups").is_none());
    assert!(userinfo(&f, &tokens).await.get("groups").is_none());
}

#[tokio::test]
async fn all_lists_every_group_in_the_client_format() {
    let f = Fixture::new().await;
    let ops = add_group(&f, "Ops", true).await;
    add_group(&f, "Elsewhere", false).await;
    set_web(&f, json!({ "id_token_groups": "all" })).await;
    // No `groups` scope needed: the app option alone decides.
    let (_, tokens) = f.web_tokens(OPENID, "ann@example.com").await;
    let mut ids = vec![f.group.to_string(), ops.to_string()];
    ids.sort();
    assert_eq!(id_claims(&f, &tokens).await["groups"], json!(ids));
    assert_eq!(userinfo(&f, &tokens).await["groups"], json!(ids));

    // The client's own groups_claim_format, picked up on refresh.
    set_web(&f, json!({ "groups_claim_format": "name" })).await;
    let (st, tokens) = f
        .refresh(tokens["refresh_token"].as_str().unwrap(), None)
        .await;
    assert_eq!(st, StatusCode::OK, "{tokens}");
    let names = json!(["Approvers", "Ops"]);
    assert_eq!(id_claims(&f, &tokens).await["groups"], names);
    // Userinfo reads the option and memberships at call time.
    assert_eq!(userinfo(&f, &tokens).await["groups"], names);
    set_web(&f, json!({ "id_token_groups": "none" })).await;
    assert!(userinfo(&f, &tokens).await.get("groups").is_none());
}

#[tokio::test]
async fn assigned_lists_only_groups_holding_a_role_on_the_client() {
    let f = Fixture::new().await;
    let user_role = add_role(&f.db, &f.web, "Web.User", "user").await;
    let app_role = add_role(&f.db, &f.web, "Web.Daemon", "application").await;
    let web_users = add_group(&f, "Web users", true).await;
    let daemons = add_group(&f, "Daemons", true).await;
    let outsiders = add_group(&f, "Outsiders", false).await;
    assign_role(&f.db, &f.web, user_role, Some(web_users), None).await;
    // A role users can't hold doesn't make the group "assigned".
    assign_role(&f.db, &f.web, app_role, Some(daemons), None).await;
    assign_role(&f.db, &f.web, user_role, Some(outsiders), None).await;
    set_web(
        &f,
        json!({ "id_token_groups": "assigned", "groups_claim_format": "name" }),
    )
    .await;
    // Approvers holds a role on orders, not on web-app: left out.
    let (_, tokens) = f
        .web_tokens(
            "openid offline_access api://orders/Orders.Read",
            "ann@example.com",
        )
        .await;
    assert_eq!(id_claims(&f, &tokens).await["groups"], json!(["Web users"]));
    // The access token still follows the resource (orders, ids, all groups).
    let at = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), "api://orders")
        .await;
    let mut all = [f.group, web_users, daemons];
    all.sort();
    let all: Vec<String> = all.iter().map(Uuid::to_string).collect();
    assert_eq!(at["groups"], json!(all));

    let (_, tokens) = f.web_tokens("openid", "ann@example.com").await;
    assert_eq!(userinfo(&f, &tokens).await["groups"], json!(["Web users"]));
}

#[tokio::test]
async fn overage_becomes_hasgroups_in_the_id_token() {
    let f = Fixture::new().await;
    set_web(
        &f,
        json!({ "id_token_groups": "all", "groups_claim_format": "name" }),
    )
    .await;
    // 200 more groups make 201 memberships: one over the limit.
    f.db.execute_unprepared(&format!(
        "WITH g AS (
             INSERT INTO groups (id, tenant_id, display_name)
             SELECT gen_random_uuid(), '{t}', 'g' || i FROM generate_series(1, 200) i
             RETURNING id
         )
         INSERT INTO group_members (tenant_id, group_id, user_id)
         SELECT '{t}', id, '{u}' FROM g",
        t = f.tenant.id,
        u = f.user.id,
    ))
    .await
    .unwrap();
    let (_, tokens) = f.web_tokens("openid", "ann@example.com").await;
    let id = id_claims(&f, &tokens).await;
    assert!(id.get("groups").is_none());
    assert_eq!(id["hasgroups"], true);
    let info = userinfo(&f, &tokens).await;
    assert!(info.get("groups").is_none());
    assert_eq!(info["hasgroups"], true);

    // `assigned` counts the filtered set: one assigned group is no overage.
    let role = add_role(&f.db, &f.web, "Web.User", "user").await;
    assign_role(&f.db, &f.web, role, Some(f.group), None).await;
    set_web(&f, json!({ "id_token_groups": "assigned" })).await;
    let (_, tokens) = f.web_tokens("openid", "ann@example.com").await;
    let id = id_claims(&f, &tokens).await;
    assert_eq!(id["groups"], json!(["Approvers"]));
    assert!(id.get("hasgroups").is_none());
}
