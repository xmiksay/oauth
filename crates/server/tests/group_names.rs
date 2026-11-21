// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Group names: unique per tenant case-insensitively (409), and emitted in
//! the `groups` claim when the resource's `groups_claim_format` is `name`.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_admin_token, app_by_client_id, audited, call, mint_user_token, user_with_roles},
};
use entity::enums::DirectoryRole::{GlobalAdmin, UserAdmin};
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};

const GROUPS: &str = "/api/v1/groups";
const SCOPE: &str = "openid offline_access api://orders/Orders.Read";

async fn set_format(f: &Fixture, format: &str) -> (StatusCode, Value) {
    let token = app_admin_token(f).await;
    let path = format!("/api/v1/applications/{}", f.orders.id);
    let body = json!({ "groups_claim_format": format });
    call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await
}

async fn orders_claims(f: &Fixture, tokens: &Value) -> serde_json::Map<String, Value> {
    f.verify_jwt(tokens["access_token"].as_str().unwrap(), "api://orders")
        .await
}

#[tokio::test]
async fn group_names_are_unique_per_tenant_case_insensitively() {
    let f = Fixture::new().await;
    let ua = user_with_roles(&f.db, f.tenant.id, "ua@example.com", &[UserAdmin]).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ua).await;
    let post = |body: Value| {
        let token = token.clone();
        let app = f.app.clone();
        async move { call(&app, Method::POST, GROUPS, Some(&token), Some(&body)).await }
    };

    // The fixture already has "Approvers".
    let (st, body) = post(json!({ "display_name": "approvers" })).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "conflict");
    let (st, ops) = post(json!({ "display_name": "Ops" })).await;
    assert_eq!(st, StatusCode::CREATED, "{ops}");
    let ops_path = format!("{GROUPS}/{}", ops["id"].as_str().unwrap());
    let patch = |body: Value| {
        let (token, app, path) = (token.clone(), f.app.clone(), ops_path.clone());
        async move { call(&app, Method::PATCH, &path, Some(&token), Some(&body)).await }
    };

    let (st, _) = patch(json!({ "display_name": "APPROVERS" })).await;
    assert_eq!(st, StatusCode::CONFLICT, "renames collide too");
    // Its own name in another case is no collision.
    let (st, body) = patch(json!({ "display_name": "OPS" })).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], "OPS");
    let id = ops["id"].as_str().unwrap().parse().unwrap();
    let updates = audited(&f.db, "group.update", id).await;
    assert_eq!(updates, [json!({ "fields": ["display_name"] })]);

    // Other tenants may reuse the name.
    f.db.execute_unprepared(&format!(
        "INSERT INTO tenants (id, slug, display_name) VALUES ('{t}', 'fabrikam', 'F');
         INSERT INTO groups (id, tenant_id, display_name) VALUES ('{g}', '{t}', 'approvers');",
        t = uuid::Uuid::now_v7(),
        g = uuid::Uuid::now_v7(),
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn groups_claim_format_is_validated_and_shown() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}", f.orders.id);
    let (st, app) = call(&f.app, Method::GET, &path, Some(&token), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(app["groups_claim_format"], "id", "the default");

    for bad in ["both", "Name", ""] {
        let (st, _) = set_format(&f, bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (st, app) = set_format(&f, "name").await;
    assert_eq!(st, StatusCode::OK, "{app}");
    assert_eq!(app["groups_claim_format"], "name");
    let (st, _) = set_format(&f, "name").await;
    assert_eq!(st, StatusCode::OK);
    let updates = audited(&f.db, "application.update", f.orders.id).await;
    assert_eq!(
        updates,
        [json!({ "client_id": "orders", "fields": ["groups_claim_format"] })],
        "unchanged values aren't audited"
    );

    let create = json!({ "display_name": "K8s", "groups_claim_format": "name" });
    let (st, app) = call(
        &f.app,
        Method::POST,
        "/api/v1/applications",
        Some(&token),
        Some(&create),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{app}");
    assert_eq!(app["groups_claim_format"], "name");

    // Not editable on built-in apps, even for a GlobalAdmin; echoing the
    // unchanged value is fine.
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let api = app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let path = format!("/api/v1/applications/{}", api.id);
    let body = json!({ "groups_claim_format": "name" });
    let (st, _) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&body)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let body = json!({ "groups_claim_format": "id" });
    let (st, body) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&body)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["groups_claim_format"], "id");
}

#[tokio::test]
async fn groups_claim_carries_ids_or_names_per_resource() {
    let f = Fixture::new().await;
    let (_, tokens) = f.web_tokens(SCOPE, "ann@example.com").await;
    let at = orders_claims(&f, &tokens).await;
    assert_eq!(at["groups"], json!([f.group.to_string()]), "ids by default");

    assert_eq!(set_format(&f, "name").await.0, StatusCode::OK);
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let (st, tokens) = f.refresh(refresh, None).await;
    assert_eq!(st, StatusCode::OK, "{tokens}");
    let at = orders_claims(&f, &tokens).await;
    assert_eq!(at["groups"], json!(["Approvers"]));
    assert_eq!(at["roles"], json!(["Orders.Approver"]), "roles unaffected");

    // Names are read at issuance: a rename shows up on the next token.
    f.db.execute_unprepared(&format!(
        "UPDATE groups SET display_name = 'Order approvers' WHERE id = '{}'",
        f.group
    ))
    .await
    .unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let (st, tokens) = f.refresh(refresh, None).await;
    assert_eq!(st, StatusCode::OK, "{tokens}");
    let at = orders_claims(&f, &tokens).await;
    assert_eq!(at["groups"], json!(["Order approvers"]));

    // Only the resource decides: userinfo-audience tokens keep ids.
    let (_, tokens) = f.web_tokens("openid", "ann@example.com").await;
    let issuer = common::ORIGIN;
    let at = f
        .verify_jwt(
            tokens["access_token"].as_str().unwrap(),
            &format!("{issuer}/oauth2/userinfo"),
        )
        .await;
    assert_eq!(at["groups"], json!([f.group.to_string()]));
}

#[tokio::test]
async fn overage_rule_is_the_same_for_names() {
    let f = Fixture::new().await;
    assert_eq!(set_format(&f, "name").await.0, StatusCode::OK);
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
    let (_, tokens) = f.web_tokens(SCOPE, "ann@example.com").await;
    let at = orders_claims(&f, &tokens).await;
    assert!(at.get("groups").is_none());
    assert_eq!(at["hasgroups"], true);

    // Back at the limit, every name is listed.
    f.db.execute_unprepared("DELETE FROM groups WHERE display_name = 'g200'")
        .await
        .unwrap();
    let (_, tokens) = f.web_tokens(SCOPE, "ann@example.com").await;
    let at = orders_claims(&f, &tokens).await;
    let names = at["groups"].as_array().unwrap();
    assert_eq!(names.len(), 200);
    assert!(names.contains(&json!("Approvers")) && names.contains(&json!("g199")));
    assert!(at.get("hasgroups").is_none());
}
