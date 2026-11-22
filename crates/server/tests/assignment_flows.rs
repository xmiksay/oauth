// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `assignment_required` meeting the other token paths: a multi-resource
//! refresh to a resource requiring assignment, an MFA-required sign-in and
//! a federated sign-in whose group mappings carry the assignment.
mod common;

use axum::http::StatusCode;
use common::{
    browser::{authorize_url, current_totp, query_of},
    federation::{Fed, code_of},
    flow::{Fixture, PASSWORD, WEB_CB},
    groups::{EMAIL, group, mapped},
    mrrt::{LEDGER, consent_to_ledger, orders_refresh_token, redeem_ok, refused, set_mfa},
    seed::{add_role, assign_role},
    upstream::Account,
};
use entity::{applications, enums::AppMfaPolicy};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr};
use serde_json::{Value, json};

async fn require(db: &sea_orm::DatabaseConnection, app: &applications::Model) {
    applications::Entity::update_many()
        .col_expr(applications::Column::AssignmentRequired, Expr::value(true))
        .filter(applications::Column::Id.eq(app.id))
        .exec(db)
        .await
        .unwrap();
}

fn error_of(location: &str) -> Option<String> {
    assert!(location.starts_with(WEB_CB), "{location}");
    let q = query_of(location);
    if q.contains_key("error") {
        assert!(!q.contains_key("code"), "{location}");
    }
    q.get("error").cloned()
}

#[tokio::test]
async fn a_multi_resource_refresh_needs_the_new_resources_assignment() {
    let f = Fixture::new().await;
    let rt = orders_refresh_token(&f).await;
    consent_to_ledger(&f).await;
    require(&f.db, &f.ledger).await;

    // Consented, but not assigned to the ledger: refused, token not burnt.
    refused(&f, &rt, LEDGER, "invalid_grant").await;
    let (st, body) = f.refresh(&rt, None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let rt = body["refresh_token"].as_str().unwrap().to_owned();

    // Assigned (through the user's group): the same request now works.
    let role = add_role(&f.db, &f.ledger, "Ledger.User", "user").await;
    assign_role(&f.db, &f.ledger, role, Some(f.group), None).await;
    let (_, body) = redeem_ok(&f, &rt, LEDGER).await;
    assert_eq!(body["scope"], LEDGER);
}

#[tokio::test]
async fn an_mfa_required_app_asks_the_second_factor_before_refusing() {
    let f = Fixture::new().await;
    f.enroll_totp(&f.user).await;
    set_mfa(&f, &f.web, AppMfaPolicy::Required).await;
    require(&f.db, &f.web).await;
    let mut browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, "openid", &[]);
    let tx = browser.authorize(&url).await.unwrap();
    // The password alone says nothing about the assignment.
    let (st, resp) = browser
        .step(
            &tx,
            "password",
            json!({ "email": "ann@example.com", "password": PASSWORD }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(resp["step"], "mfa", "{resp}");
    let (st, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    let back = resp["redirect"].as_str().unwrap();
    assert_eq!(error_of(back).as_deref(), Some("access_denied"));
    assert!(!browser.has_session());
}

async fn federated(fed: &Fed, idp: &str, claims: Value) -> String {
    let mut account = Account::new("upstream-sub-1", EMAIL);
    account.extra = claims;
    fed.up.set_account(account);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), idp).await;
    location
}

#[tokio::test]
async fn a_mapped_group_carries_the_assignment_of_a_federated_sign_in() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let eng = group(&fed, "Eng").await;
    mapped(&fed, &idp, "groups", "eng", eng).await;
    let role = add_role(&fed.f.db, &fed.f.web, "Web.User", "user").await;
    assign_role(&fed.f.db, &fed.f.web, role, Some(eng), None).await;
    require(&fed.f.db, &fed.f.web).await;

    // The mapping is applied before the check: the first (JIT) sign-in is
    // already assigned.
    let location = federated(&fed, &idp, json!({ "groups": ["eng"] })).await;
    let code = code_of(&location);
    let (st, tokens) = fed
        .f
        .redeem(&fed.f.web, Some(&fed.f.web_secret), &code, WEB_CB)
        .await;
    assert_eq!(st, StatusCode::OK, "{tokens}");

    // The upstream drops the value: the mapped membership goes with this
    // sign-in, and so does the assignment.
    let location = federated(&fed, &idp, json!({})).await;
    assert_eq!(error_of(&location).as_deref(), Some("access_denied"));
}
