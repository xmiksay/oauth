// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `groups` as an OIDC scope (accepted, advertised, kept on refresh / MRRT,
//! never a resource scope value) and the `id_token_groups` management field.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{
        app_admin_token, app_by_client_id, audited, call, mint_user_token, post, user_with_roles,
    },
    mrrt::{LEDGER, consent_to_ledger, redeem_ok, refused},
};
use entity::enums::{DirectoryRole::GlobalAdmin, IdTokenGroups};
use serde_json::{Value, json};

async fn patch_web(f: &Fixture, body: Value) -> (StatusCode, Value) {
    let token = app_admin_token(f).await;
    let path = format!("/api/v1/applications/{}", f.web.id);
    call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await
}

#[tokio::test]
async fn id_token_groups_is_validated_audited_and_shown() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}", f.web.id);
    let (st, app) = call(&f.app, Method::GET, &path, Some(&token), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(app["id_token_groups"], "none", "the default");

    for bad in ["some", "All", ""] {
        let (st, _) = patch_web(&f, json!({ "id_token_groups": bad })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (st, app) = patch_web(&f, json!({ "id_token_groups": "assigned" })).await;
    assert_eq!(st, StatusCode::OK, "{app}");
    assert_eq!(app["id_token_groups"], "assigned");
    assert_eq!(
        patch_web(&f, json!({ "id_token_groups": "assigned" }))
            .await
            .0,
        StatusCode::OK
    );
    let updates = audited(&f.db, "application.update", f.web.id).await;
    assert_eq!(
        updates,
        [json!({ "client_id": "web-app", "fields": ["id_token_groups"] })],
        "unchanged values aren't audited"
    );

    let create = json!({ "display_name": "Headlamp", "id_token_groups": "all" });
    let (st, app) = post(&f, &token, "/api/v1/applications", create).await;
    assert_eq!(st, StatusCode::CREATED, "{app}");
    assert_eq!(app["id_token_groups"], "all");
}

#[tokio::test]
async fn groups_is_an_advertised_oidc_scope() {
    let f = Fixture::new().await;
    let (st, text) = common::get(&f.app, "/.well-known/openid-configuration").await;
    assert_eq!(st, StatusCode::OK);
    let meta: Value = serde_json::from_str(&text).unwrap();
    let supported = meta["scopes_supported"].as_array().unwrap();
    assert!(supported.contains(&json!("groups")), "{meta}");
    let claims = meta["claims_supported"].as_array().unwrap();
    assert!(claims.contains(&json!("groups")), "{meta}");

    let (_, tokens) = f
        .web_tokens("openid groups api://orders/Orders.Read", "ann@example.com")
        .await;
    let granted: Vec<&str> = tokens["scope"].as_str().unwrap().split(' ').collect();
    assert!(granted.contains(&"groups"), "{tokens}");
    // Not a resource scope: it never reaches the access token's `scp`.
    let at = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["scp"], "Orders.Read");
}

#[tokio::test]
async fn groups_cannot_be_a_resource_scope_value() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}/scopes", f.orders.id);
    for value in ["groups", "GROUPS"] {
        let (st, body) = post(&f, &token, &path, json!({ "value": value })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{value}: {body}");
    }
    let (st, body) = post(&f, &token, &path, json!({ "value": "Groups.Read" })).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn groups_scope_is_kept_on_refresh_and_mrrt() {
    let f = Fixture::new().await;
    let (st, _) = patch_web(&f, json!({ "id_token_groups": "all" })).await;
    assert_eq!(st, StatusCode::OK);
    consent_to_ledger(&f).await;
    let (_, tokens) = f
        .web_tokens(
            "openid offline_access groups api://orders/Orders.Read",
            "ann@example.com",
        )
        .await;
    let rt = tokens["refresh_token"].as_str().unwrap();

    // Multi-resource refresh to the ledger, narrowing the OIDC scopes.
    let (rt, body) = redeem_ok(&f, rt, &format!("openid groups {LEDGER}")).await;
    let granted: Vec<&str> = body["scope"].as_str().unwrap().split(' ').collect();
    assert!(granted.contains(&"groups"), "{body}");
    let id = f
        .verify_jwt(body["id_token"].as_str().unwrap(), "web-app")
        .await;
    assert_eq!(id["groups"], json!([f.group.to_string()]));

    // A plain refresh keeps the original grant, `groups` included.
    let (st, body) = f.refresh(&rt, None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body["scope"].as_str().unwrap().contains("groups"), "{body}");
}

#[tokio::test]
async fn refresh_cannot_add_the_groups_scope() {
    let f = Fixture::new().await;
    let (_, tokens) = f
        .web_tokens("openid offline_access", "ann@example.com")
        .await;
    let rt = tokens["refresh_token"].as_str().unwrap();
    refused(&f, rt, "openid groups", "invalid_scope").await;
}

#[tokio::test]
async fn id_token_groups_is_not_editable_on_builtin_apps() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let portal = app_by_client_id(&f.db, f.tenant.id, "admin-portal").await;
    let path = format!("/api/v1/applications/{}", portal.id);
    let body = json!({ "id_token_groups": "all" });
    let (st, _) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&body)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let row = app_by_client_id(&f.db, f.tenant.id, "admin-portal").await;
    assert_eq!(row.id_token_groups, IdTokenGroups::None);
    assert!(
        audited(&f.db, "application.update", portal.id)
            .await
            .is_empty()
    );
}
