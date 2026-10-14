// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Updating and deleting what hangs off an app registration: scopes, roles,
//! required permissions, secrets and app role assignments.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_admin_token, app_by_client_id, call, mint_user_token, post, user_with_roles},
};
use entity::{app_scopes, enums::DirectoryRole::GlobalAdmin};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Value, json};

const APPS: &str = "/api/v1/applications";
const ASSIGN: &str = "/api/v1/role-assignments";

async fn item_id(f: &Fixture, token: &str, path: &str, value: &str) -> String {
    let (_, list) = call(&f.app, Method::GET, path, Some(token), None).await;
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["value"] == value)
        .unwrap_or_else(|| panic!("{value} not in {list}"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn deleting_a_scope_withdraws_it_everywhere() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let scopes = format!("{APPS}/{}/scopes", f.orders.id);
    let (_, tokens) = f
        .web_tokens(
            "offline_access api://orders/Orders.Read api://orders/Orders.Write",
            "ann@example.com",
        )
        .await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    // PATCH: description / admin flag; empty body is a no-op; value is fixed.
    let read = format!(
        "{scopes}/{}",
        item_id(&f, &token, &scopes, "Orders.Read").await
    );
    let (st, body) = call(
        &f.app,
        Method::PATCH,
        &read,
        Some(&token),
        Some(&json!({ "description": "Read" })),
    )
    .await;
    assert_eq!(
        (st, body["description"].as_str()),
        (StatusCode::OK, Some("Read"))
    );
    let (st, same) = call(&f.app, Method::PATCH, &read, Some(&token), Some(&json!({}))).await;
    assert_eq!(
        (st, same["description"].as_str()),
        (StatusCode::OK, Some("Read"))
    );
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &read,
        Some(&token),
        Some(&json!({ "value": "X" })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Robustness: a scope gone behind the API's back is no longer minted.
    app_scopes::Entity::delete_many()
        .filter(app_scopes::Column::ApplicationId.eq(f.orders.id))
        .filter(app_scopes::Column::Value.eq("Orders.Write"))
        .exec(&f.db)
        .await
        .unwrap();
    let (st, renewed) = f.refresh(&refresh, None).await;
    assert_eq!(st, StatusCode::OK, "{renewed}");
    let claims = f
        .verify_jwt(renewed["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(claims["scp"], "Orders.Read");
    let refresh = renewed["refresh_token"].as_str().unwrap().to_owned();

    // Through the API: the grant loses the value and the family is revoked.
    assert_eq!(
        call(&f.app, Method::DELETE, &read, Some(&token), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &read, Some(&token), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (st, body) = f.refresh(&refresh, None).await;
    assert_eq!(
        (st, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let consents = format!("/api/v1/consents?user_id={}", f.user.id);
    let (_, grants) = call(&f.app, Method::GET, &consents, Some(&token), None).await;
    let held: Vec<&Value> = grants["items"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["scopes"].as_array().unwrap())
        .collect();
    assert!(!held.iter().any(|s| *s == "Orders.Read"), "{grants}");
}

#[tokio::test]
async fn roles_permissions_secrets_and_assignments() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let roles = format!("{APPS}/{}/roles", f.orders.id);
    let approver = format!(
        "{roles}/{}",
        item_id(&f, &token, &roles, "Orders.Approver").await
    );
    let (st, body) = call(
        &f.app,
        Method::PATCH,
        &approver,
        Some(&token),
        Some(&json!({ "display_name": "Approve" })),
    )
    .await;
    assert_eq!(
        (st, body["display_name"].as_str()),
        (StatusCode::OK, Some("Approve"))
    );
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &approver,
        Some(&token),
        Some(&json!({ "allowed_member_types": [] })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, same) = call(
        &f.app,
        Method::PATCH,
        &approver,
        Some(&token),
        Some(&json!({})),
    )
    .await;
    assert_eq!(
        (st, same["display_name"].as_str()),
        (StatusCode::OK, Some("Approve"))
    );

    // Assignments: create, delete; the group assignment dies with the role.
    let role_id = approver.rsplit('/').next().unwrap().to_owned();
    let to_ann =
        json!({ "app_role_id": role_id, "principal_type": "user", "principal_id": f.user.id });
    let (st, created) = post(&f, &token, ASSIGN, to_ann).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let one = format!("{ASSIGN}/{}", created["id"].as_str().unwrap());
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&token), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&token), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &approver, Some(&token), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let filter = format!("{ASSIGN}?resource_application_id={}", f.orders.id);
    let (_, left) = call(&f.app, Method::GET, &filter, Some(&token), None).await;
    assert_eq!(left["items"].as_array().unwrap().len(), 0, "{left}");

    // Management-API role assignments: removable by a GlobalAdmin only.
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let api = app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let api_roles = format!("{APPS}/{}/roles", api.id);
    let read_all = item_id(&f, &ga, &api_roles, "Directory.Read.All").await;
    let body = json!({ "app_role_id": read_all, "principal_type": "application", "principal_id": f.web.id });
    let (_, created) = post(&f, &ga, ASSIGN, body).await;
    let one = format!("{ASSIGN}/{}", created["id"].as_str().unwrap());
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&token), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&ga), None).await.0,
        StatusCode::NO_CONTENT
    );

    // Required permissions: add, delete, gone.
    let perms = format!("{APPS}/{}/required-permissions", f.web.id);
    let body = json!({ "resource_application_id": f.ledger.id, "type": "delegated", "value": "Ledger.Read" });
    let (st, perm) = post(&f, &token, &perms, body).await;
    assert_eq!(st, StatusCode::CREATED, "{perm}");
    let one = format!("{perms}/{}", perm["id"].as_str().unwrap());
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&token), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&token), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // Secrets: deleting the seeded secret ends client authentication.
    let secrets = format!("{APPS}/{}/secrets", f.web.id);
    let (_, list) = call(&f.app, Method::GET, &secrets, Some(&token), None).await;
    let one = format!("{secrets}/{}", list["items"][0]["id"].as_str().unwrap());
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&token), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let form = [
        ("grant_type", "client_credentials"),
        ("scope", "api://orders/.default"),
    ];
    let (st, _, _) = f
        .post_form(
            "/oauth2/token",
            &form,
            Some(("web-app", f.web_secret.as_str())),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}
