// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Every mutating route against callers that must not reach it, and
//! app-only access following live role assignments.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{call, mint_app_token, mint_user_token, post, user_with_roles},
};
use entity::enums::DirectoryRole::{ApplicationAdmin, GlobalAdmin, UserAdmin};
use oauth_server::directory::builtin_apps;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq)]
enum Area {
    Directory,
    Applications,
    /// Directory roles and tenant settings: GlobalAdmin only.
    GlobalAdmin,
}

fn routes() -> Vec<(Method, String, Value, Area)> {
    use Area::{Applications as A, Directory as D, GlobalAdmin as G};
    let t = "/api/v1";
    let (x, y) = (Uuid::now_v7(), Uuid::now_v7());
    let app = format!("{t}/applications/{x}");
    let none = Value::Null;
    vec![
        (
            Method::POST,
            format!("{t}/users"),
            json!({ "email": "z@example.com", "display_name": "Z" }),
            D,
        ),
        (Method::PATCH, format!("{t}/users/{x}"), json!({}), D),
        (Method::DELETE, format!("{t}/users/{x}"), none.clone(), D),
        (
            Method::POST,
            format!("{t}/users/{x}/reset-password"),
            json!({}),
            D,
        ),
        (
            Method::POST,
            format!("{t}/users/{x}/reset-mfa"),
            none.clone(),
            D,
        ),
        (
            Method::POST,
            format!("{t}/users/{x}/revoke-sessions"),
            none.clone(),
            D,
        ),
        (
            Method::POST,
            format!("{t}/groups"),
            json!({ "display_name": "G" }),
            D,
        ),
        (Method::PATCH, format!("{t}/groups/{x}"), json!({}), D),
        (Method::DELETE, format!("{t}/groups/{x}"), none.clone(), D),
        (
            Method::POST,
            format!("{t}/groups/{x}/members"),
            json!({ "user_id": y }),
            D,
        ),
        (
            Method::DELETE,
            format!("{t}/groups/{x}/members/{y}"),
            none.clone(),
            D,
        ),
        (
            Method::POST,
            format!("{t}/directory-roles"),
            json!({ "user_id": y, "role": "UserAdmin" }),
            G,
        ),
        (
            Method::DELETE,
            format!("{t}/directory-roles/{x}"),
            none.clone(),
            G,
        ),
        (Method::PATCH, format!("{t}/settings"), json!({}), G),
        (
            Method::POST,
            format!("{t}/applications"),
            json!({ "display_name": "A" }),
            A,
        ),
        (Method::PATCH, app.clone(), json!({}), A),
        (Method::DELETE, app.clone(), none.clone(), A),
        (Method::POST, format!("{app}/secrets"), json!({}), A),
        (
            Method::DELETE,
            format!("{app}/secrets/{y}"),
            none.clone(),
            A,
        ),
        (
            Method::POST,
            format!("{app}/scopes"),
            json!({ "value": "S.Read" }),
            A,
        ),
        (Method::PATCH, format!("{app}/scopes/{y}"), json!({}), A),
        (Method::DELETE, format!("{app}/scopes/{y}"), none.clone(), A),
        (
            Method::POST,
            format!("{app}/roles"),
            json!({ "value": "R", "display_name": "R", "allowed_member_types": ["user"] }),
            A,
        ),
        (Method::PATCH, format!("{app}/roles/{y}"), json!({}), A),
        (Method::DELETE, format!("{app}/roles/{y}"), none.clone(), A),
        (
            Method::POST,
            format!("{app}/required-permissions"),
            json!({ "resource_application_id": y, "type": "delegated", "value": "S" }),
            A,
        ),
        (
            Method::DELETE,
            format!("{app}/required-permissions/{y}"),
            none.clone(),
            A,
        ),
        (
            Method::POST,
            format!("{t}/role-assignments"),
            json!({ "app_role_id": x, "principal_type": "user", "principal_id": y }),
            A,
        ),
        (
            Method::DELETE,
            format!("{t}/role-assignments/{x}"),
            none.clone(),
            A,
        ),
        (
            Method::POST,
            format!("{t}/consents"),
            json!({ "client_application_id": x, "resource_application_id": y }),
            A,
        ),
        (Method::DELETE, format!("{t}/consents/{x}"), none, A),
    ]
}

#[tokio::test]
async fn mutating_routes_refuse_callers_without_the_right_role() {
    let f = Fixture::new().await;
    let (db, cfg, t) = (&f.db, &f.config, &f.tenant);
    let ua = user_with_roles(db, t.id, "ua@example.com", &[UserAdmin]).await;
    let aa = user_with_roles(db, t.id, "aa@example.com", &[ApplicationAdmin]).await;
    let ua = mint_user_token(db, cfg, t, &ua).await;
    let aa = mint_user_token(db, cfg, t, &aa).await;
    let plain = mint_user_token(db, cfg, t, &f.user).await;
    let reader = mint_app_token(db, cfg, t, Some(builtin_apps::ROLE_READ_ALL)).await;
    let writer = mint_app_token(db, cfg, t, Some(builtin_apps::ROLE_READ_WRITE_ALL)).await;

    let mut checked = 0;
    for (method, path, body, area) in routes() {
        let body = (!body.is_null()).then_some(&body);
        let mut refused = vec![("plain member", &plain), ("Read.All app", &reader)];
        if area != Area::Applications {
            refused.push(("ApplicationAdmin", &aa));
        }
        if area != Area::Directory {
            refused.push(("UserAdmin", &ua));
        }
        if area == Area::GlobalAdmin {
            refused.push(("ReadWrite.All app", &writer));
        }
        for (who, token) in refused {
            let (st, resp) = call(&f.app, method.clone(), &path, Some(token), body).await;
            assert_eq!(st, StatusCode::FORBIDDEN, "{who} {method} {path}: {resp}");
            checked += 1;
        }
    }
    // 31 routes × (member, Read.All app) + ApplicationAdmin × 14 + UserAdmin
    // × 20 + ReadWrite.All app × 3 (GlobalAdmin-only routes).
    assert_eq!(checked, 99);
}

#[tokio::test]
async fn app_only_access_follows_live_role_assignments() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let apps = "/api/v1/applications";
    let (_, svc) = post(
        &f,
        &ga,
        apps,
        json!({ "client_id": "svc", "display_name": "Svc" }),
    )
    .await;
    let svc_path = format!("{apps}/{}", svc["id"].as_str().unwrap());
    let (_, secret) = post(&f, &ga, &format!("{svc_path}/secrets"), json!({})).await;
    let api = common::mgmt::app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let (_, roles) = call(
        &f.app,
        Method::GET,
        &format!("{apps}/{}/roles", api.id),
        Some(&ga),
        None,
    )
    .await;
    let rw = roles["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["value"] == builtin_apps::ROLE_READ_WRITE_ALL)
        .unwrap()["id"]
        .clone();
    let assign =
        json!({ "app_role_id": rw, "principal_type": "application", "principal_id": svc["id"] });
    let (_, assignment) = post(&f, &ga, "/api/v1/role-assignments", assign).await;

    let form = [
        ("grant_type", "client_credentials"),
        ("scope", "api://management-api/.default"),
    ];
    let basic = Some(("svc", secret["secret"].as_str().unwrap()));
    let (st, _, body) = f.post_form("/oauth2/token", &form, basic).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_owned();
    let users = "/api/v1/users";
    let new_user = |n: u8| json!({ "email": format!("u{n}@example.com"), "display_name": "U" });
    assert_eq!(
        post(&f, &token, users, new_user(1)).await.0,
        StatusCode::CREATED
    );

    // The token's `roles` claim still says ReadWrite.All; access doesn't.
    let one = format!(
        "/api/v1/role-assignments/{}",
        assignment["id"].as_str().unwrap()
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &one, Some(&ga), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&f, &token, users, new_user(2)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&f.app, Method::GET, users, Some(&token), None).await.0,
        StatusCode::FORBIDDEN
    );

    // A deleted app keeps nothing either.
    let (_, _) = post(
        &f,
        &ga,
        "/api/v1/role-assignments",
        json!({ "app_role_id": rw, "principal_type": "application", "principal_id": svc["id"] }),
    )
    .await;
    assert_eq!(
        post(&f, &token, users, new_user(3)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &svc_path, Some(&ga), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&f, &token, users, new_user(4)).await.0,
        StatusCode::FORBIDDEN
    );
}
