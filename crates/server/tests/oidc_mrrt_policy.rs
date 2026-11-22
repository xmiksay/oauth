// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Multi-resource refresh: MFA policies, built-in clients and a deleted
//! scope reaching the opaque tokens minted for another resource.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_admin_token, call},
    mrrt::{
        LEDGER, consent_to_ledger, live_ledger_tokens, orders_refresh_token, redeem_ok, refused,
        set_mfa,
    },
};
use entity::{
    app_scopes, applications,
    enums::{AppMfaPolicy, MfaPolicy},
    tenants,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;

#[tokio::test]
async fn multi_factor_sign_in_reaches_an_mfa_resource() {
    let f = Fixture::new().await;
    f.enroll_totp(&f.user).await;
    // The sign-in answers the TOTP step, so its `amr` is multi-factor.
    let rt = orders_refresh_token(&f).await;
    consent_to_ledger(&f).await;
    set_mfa(&f, &f.ledger, AppMfaPolicy::Required).await;
    let (_, body) = redeem_ok(&f, &rt, LEDGER).await;
    assert_eq!(body["scope"], LEDGER);
}

#[tokio::test]
async fn tenant_mfa_policy_refuses_a_single_factor_token() {
    let f = Fixture::new().await;
    let rt = orders_refresh_token(&f).await;
    consent_to_ledger(&f).await;
    let mut tenant: tenants::ActiveModel = f.tenant.clone().into();
    tenant.mfa_policy = Set(MfaPolicy::Required);
    tenant.update(&f.db).await.unwrap();
    refused(&f, &rt, LEDGER, "invalid_grant").await;
    assert_eq!(live_ledger_tokens(&f).await, 0);
}

#[tokio::test]
async fn built_in_clients_are_pre_consented() {
    let f = Fixture::new().await;
    let rt = orders_refresh_token(&f).await;
    // No grant for the ledger: an ordinary client is refused …
    refused(&f, &rt, LEDGER, "invalid_grant").await;
    // … a built-in one (as at authorize) is not.
    let mut web: applications::ActiveModel = f.web.clone().into();
    web.builtin = Set(true);
    web.update(&f.db).await.unwrap();
    let (_, body) = redeem_ok(&f, &rt, LEDGER).await;
    assert_eq!(body["scope"], LEDGER);
}

#[tokio::test]
async fn deleting_a_scope_revokes_tokens_minted_for_it() {
    let f = Fixture::new().await;
    let rt = orders_refresh_token(&f).await;
    consent_to_ledger(&f).await;
    // The ledger token belongs to the orders family, not to a ledger one.
    let (rt, body) = redeem_ok(&f, &rt, LEDGER).await;
    let access = body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(live_ledger_tokens(&f).await, 1);

    let scope = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(f.ledger.id))
        .filter(app_scopes::Column::Value.eq("Ledger.Read"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}/scopes/{}", f.ledger.id, scope.id);
    let (status, body) = call(&f.app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    assert_eq!(live_ledger_tokens(&f).await, 0);
    let introspect = [("token", access.as_str())];
    let basic = Some(("ledger", f.ledger_secret.as_str()));
    let (_, _, body) = f.post_form("/oauth2/introspect", &introspect, basic).await;
    assert_eq!(body, json!({ "active": false }));
    // The orders family is untouched and can't re-mint the scope.
    refused(&f, &rt, LEDGER, "invalid_scope").await;
    redeem_ok(&f, &rt, "api://orders/Orders.Read").await;
}
