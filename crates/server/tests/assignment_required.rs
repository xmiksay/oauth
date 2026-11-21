// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Per-application `assignment_required`: authorize, code redemption,
//! refresh and client credentials refuse principals without one of the
//! app's roles (direct or via a group).
mod common;

use axum::http::{Method, StatusCode};
use common::{
    browser::{authorize_url, current_totp, query_of},
    flow::{Fixture, PASSWORD, WEB_CB},
    mgmt::{app_admin_token, app_by_client_id, audited, call, mint_user_token, user_with_roles},
    seed::{add_role, assign_role, insert},
};
use entity::{
    app_role_assignments, applications, consent_grants, enums::DirectoryRole::GlobalAdmin,
    group_members,
};
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr};
use serde_json::{Value, json};
use uuid::Uuid;

const OPENID: &str = "openid offline_access";
const ORDERS: &str = "openid offline_access api://orders/Orders.Read";
const TOKEN: &str = "/oauth2/token";

async fn require(f: &Fixture, app: &applications::Model, on: bool) {
    applications::Entity::update_many()
        .col_expr(applications::Column::AssignmentRequired, Expr::value(on))
        .filter(applications::Column::Id.eq(app.id))
        .exec(&f.db)
        .await
        .unwrap();
}

async fn assign_user(f: &Fixture, resource: &applications::Model, role: Uuid) {
    insert(
        &f.db,
        app_role_assignments::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(resource.tenant_id),
            resource_application_id: Set(resource.id),
            app_role_id: Set(role),
            user_id: Set(Some(f.user.id)),
            group_id: Set(None),
            client_application_id: Set(None),
            ..Default::default()
        },
    )
    .await;
}

async fn unassign_all(f: &Fixture, resource: &applications::Model) {
    app_role_assignments::Entity::delete_many()
        .filter(app_role_assignments::Column::ResourceApplicationId.eq(resource.id))
        .exec(&f.db)
        .await
        .unwrap();
}

fn error_of(location: &str) -> String {
    let q = query_of(location);
    assert_eq!(
        q.get("state").map(String::as_str),
        Some("st-1"),
        "{location}"
    );
    assert!(!q.contains_key("code"), "{location}");
    q.get("error").cloned().unwrap_or_default()
}

fn web_url(scope: &str, extra: &[(&str, &str)]) -> String {
    authorize_url("web-app", WEB_CB, scope, extra)
}

#[tokio::test]
async fn the_flag_is_managed_and_audited() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}", f.web.id);
    let (st, app) = call(&f.app, Method::GET, &path, Some(&token), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(app["assignment_required"], false, "the default");
    let on = json!({ "assignment_required": true });
    for _ in 0..2 {
        let (st, app) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&on)).await;
        assert_eq!(st, StatusCode::OK, "{app}");
        assert_eq!(app["assignment_required"], true);
    }
    assert_eq!(
        audited(&f.db, "application.update", f.web.id).await,
        [json!({ "client_id": "web-app", "fields": ["assignment_required"] })],
        "unchanged values aren't audited"
    );
    let bad = json!({ "assignment_required": "yes" });
    let (st, _) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&bad)).await;
    assert!(st.is_client_error());

    let create = json!({ "display_name": "HR", "assignment_required": true });
    let apps = "/api/v1/applications";
    let (st, app) = call(&f.app, Method::POST, apps, Some(&token), Some(&create)).await;
    assert_eq!(st, StatusCode::CREATED, "{app}");
    assert_eq!(app["assignment_required"], true);

    // Built-in apps can't require assignment (it would lock users out of
    // the portals), not even by a GlobalAdmin.
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let api = app_by_client_id(&f.db, f.tenant.id, "my-account").await;
    let path = format!("/api/v1/applications/{}", api.id);
    let (st, _) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&on)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let off = json!({ "assignment_required": false });
    let (st, body) = call(&f.app, Method::PATCH, &path, Some(&ga), Some(&off)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_unassigned_user_is_refused_after_sign_in_and_with_a_session() {
    let f = Fixture::new().await;
    // A session made while the app was open.
    let (mut browser, _) = f.web_tokens(OPENID, "ann@example.com").await;
    require(&f, &f.web, true).await;

    // Fresh sign-in: the redirect carries access_denied, no session is made.
    let mut fresh = f.browser();
    let tx = fresh.authorize(&web_url(OPENID, &[])).await.unwrap();
    let back = fresh.complete_login(&tx, "ann@example.com").await;
    assert!(back.starts_with(WEB_CB), "{back}");
    assert_eq!(error_of(&back), "access_denied");
    assert!(!fresh.has_session());

    // Existing session, with and without prompt=none.
    for extra in [&[][..], &[("prompt", "none")][..]] {
        let back = browser
            .authorize(&web_url(OPENID, extra))
            .await
            .unwrap_err();
        assert_eq!(error_of(&back), "access_denied", "{extra:?}");
    }
    // Never redirected before the redirect URI matched.
    let url = authorize_url("web-app", "https://evil.example/cb", OPENID, &[]);
    let (st, location, _) = browser.get(&url).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(location.is_none());

    // Other apps are unaffected.
    let url = authorize_url("spa-app", common::flow::SPA_CB, OPENID, &[]);
    let back = browser.authorize(&url).await.unwrap_err();
    assert!(query_of(&back).contains_key("code"), "{back}");
}

#[tokio::test]
async fn a_direct_or_group_assignment_admits_the_user() {
    let f = Fixture::new().await;
    require(&f, &f.web, true).await;
    let role = add_role(&f.db, &f.web, "Web.User", "user").await;
    assign_user(&f, &f.web, role).await;
    f.web_tokens(OPENID, "ann@example.com").await;

    unassign_all(&f, &f.web).await;
    assign_role(&f.db, &f.web, role, Some(f.group), None).await;
    f.web_tokens(OPENID, "ann@example.com").await;

    // A role assigned to the user that only applications may hold doesn't
    // count (it would never become a `roles` claim).
    unassign_all(&f, &f.web).await;
    let app_only = add_role(&f.db, &f.web, "Web.Sync", "application").await;
    assign_user(&f, &f.web, app_only).await;
    let mut browser = f.browser();
    let tx = browser.authorize(&web_url(OPENID, &[])).await.unwrap();
    let back = browser.complete_login(&tx, "ann@example.com").await;
    assert_eq!(error_of(&back), "access_denied");
}

#[tokio::test]
async fn the_resource_requires_the_users_assignment() {
    let f = Fixture::new().await;
    // `orders` gives the user's group Orders.Approver.
    require(&f, &f.orders, true).await;
    let (mut browser, tokens) = f.web_tokens(ORDERS, "ann@example.com").await;
    assert!(tokens["access_token"].is_string());

    require(&f, &f.ledger, true).await;
    let ledger = "openid api://ledger/Ledger.Read";
    let back = browser.authorize(&web_url(ledger, &[])).await.unwrap_err();
    assert_eq!(error_of(&back), "access_denied");
    // The user is never asked to consent to an app they can't use.
    let mut fresh = f.browser();
    let tx = fresh.authorize(&web_url(ledger, &[])).await.unwrap();
    let back = fresh.complete_login(&tx, "ann@example.com").await;
    assert_eq!(error_of(&back), "access_denied");
}

#[tokio::test]
async fn an_assignment_removed_on_the_consent_screen_stores_no_grant() {
    let f = Fixture::new().await;
    require(&f, &f.orders, true).await;
    let mut browser = f.browser();
    let tx = browser.authorize(&web_url(ORDERS, &[])).await.unwrap();
    let password = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (mut st, mut resp) = browser.step(&tx, "password", password).await;
    if resp["step"] == "mfa" {
        let code = json!({ "code": current_totp() });
        (st, resp) = browser.step(&tx, "totp", code).await;
    }
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(resp["step"], "consent", "{resp}");

    unassign_all(&f, &f.orders).await;
    let approve = json!({ "approve": true, "scopes": ["Orders.Read"] });
    let (st, resp) = browser.step(&tx, "consent", approve).await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(
        error_of(resp["redirect"].as_str().unwrap()),
        "access_denied"
    );
    assert!(!browser.has_session());
    let grants = consent_grants::Entity::find()
        .filter(consent_grants::Column::ResourceApplicationId.eq(f.orders.id))
        .all(&f.db)
        .await
        .unwrap();
    assert!(grants.is_empty(), "{grants:?}");
}

#[tokio::test]
async fn an_assignment_removed_before_redemption_fails_the_code() {
    let f = Fixture::new().await;
    require(&f, &f.orders, true).await;
    let code = f
        .browser()
        .login_for_code(&web_url(ORDERS, &[]), "ann@example.com")
        .await;
    unassign_all(&f, &f.orders).await;
    let (st, body) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

#[tokio::test]
async fn the_client_rechecks_its_assignment_on_redemption() {
    let f = Fixture::new().await;
    let role = add_role(&f.db, &f.web, "Web.User", "user").await;
    assign_user(&f, &f.web, role).await;
    require(&f, &f.web, true).await;
    let code = f
        .browser()
        .login_for_code(&web_url(OPENID, &[]), "ann@example.com")
        .await;
    unassign_all(&f, &f.web).await;
    let (st, body) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "{body}");

    // A code issued while the app was open fails once the flag goes on.
    require(&f, &f.web, false).await;
    let code = f
        .browser()
        .login_for_code(&web_url(OPENID, &[]), "ann@example.com")
        .await;
    require(&f, &f.web, true).await;
    let (st, body) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

async fn leave_group(f: &Fixture) {
    group_members::Entity::delete_many()
        .filter(group_members::Column::GroupId.eq(f.group))
        .filter(group_members::Column::UserId.eq(f.user.id))
        .exec(&f.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn refresh_rechecks_the_assignment() {
    let f = Fixture::new().await;
    require(&f, &f.orders, true).await;
    let (_, tokens) = f.web_tokens(ORDERS, "ann@example.com").await;
    let (st, tokens) = f
        .refresh(tokens["refresh_token"].as_str().unwrap(), None)
        .await;
    assert_eq!(st, StatusCode::OK, "{tokens}");
    let rt = tokens["refresh_token"].as_str().unwrap().to_owned();

    // The group membership that carried the role goes away.
    leave_group(&f).await;
    let (st, body) = f.refresh(&rt, None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // The refused request didn't burn the token: narrowed to the OIDC
    // scopes (no resource), it still works.
    let (st, body) = f.refresh(&rt, Some("openid")).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let rt = body["refresh_token"].as_str().unwrap().to_owned();

    // The client itself requiring assignment refuses every refresh.
    require(&f, &f.web, true).await;
    let (st, body) = f.refresh(&rt, Some("openid")).await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // Assigned again (via a group): refreshes work again.
    let role = add_role(&f.db, &f.web, "Web.User", "user").await;
    assign_role(&f.db, &f.web, role, Some(f.group), None).await;
    insert(
        &f.db,
        group_members::ActiveModel {
            tenant_id: Set(f.tenant.id),
            group_id: Set(f.group),
            user_id: Set(f.user.id),
            ..Default::default()
        },
    )
    .await;
    let (st, body) = f.refresh(&rt, None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

async fn client_credentials(f: &Fixture) -> (StatusCode, Value) {
    let form = [
        ("grant_type", "client_credentials"),
        ("scope", "api://orders/.default"),
    ];
    let basic = Some(("web-app", f.web_secret.as_str()));
    let (st, _, body) = f.post_form(TOKEN, &form, basic).await;
    (st, body)
}

#[tokio::test]
async fn client_credentials_require_the_apps_assignment() {
    let f = Fixture::new().await;
    let (st, body) = client_credentials(&f).await;
    assert_eq!(st, StatusCode::OK, "open by default: {body}");

    require(&f, &f.orders, true).await;
    let (st, body) = client_credentials(&f).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // A user-only role assigned to the app doesn't count.
    let auditor = add_role(&f.db, &f.orders, "Orders.Auditor", "user").await;
    assign_role(&f.db, &f.orders, auditor, None, Some(f.web.id)).await;
    let (_, body) = client_credentials(&f).await;
    assert_eq!(body["error"], "invalid_grant", "{body}");

    let sync = add_role(&f.db, &f.orders, "Orders.Sync", "application").await;
    assign_role(&f.db, &f.orders, sync, None, Some(f.web.id)).await;
    let (st, body) = client_credentials(&f).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}
