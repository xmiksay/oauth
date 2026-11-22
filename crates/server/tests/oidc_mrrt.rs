// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Multi-resource refresh tokens: one refresh token redeemed for every
//! resource the user consented to for the client, on live consent and MFA.
mod common;

use axum::http::StatusCode;
use common::{
    flow::Fixture,
    seed::{add_app, add_scope},
};
use entity::{
    applications, consent_grants,
    enums::{AccessTokenFormat, AppMfaPolicy, ClientType, SigningAlg},
    opaque_access_tokens,
};
use oauth_server::{
    consent,
    directory::{self, NewTenant},
    tokens::refresh,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;

const LEDGER: &str = "api://ledger/Ledger.Read";

fn error(reply: &(StatusCode, Value)) -> (StatusCode, Option<&str>) {
    (reply.0, reply.1["error"].as_str())
}

/// Redeems `rt` for `scope`, expecting success; returns the rotated token.
async fn redeem_ok(f: &Fixture, rt: &str, scope: &str) -> (String, Value) {
    let (status, body) = f.refresh(rt, Some(scope)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (body["refresh_token"].as_str().unwrap().to_owned(), body)
}

async fn consent_to_ledger(f: &Fixture) {
    let values = ["Ledger.Read".to_owned()];
    consent::store_grant(
        &f.db,
        f.tenant.id,
        f.web.id,
        f.ledger.id,
        Some(f.user.id),
        &values,
    )
    .await
    .unwrap();
}

async fn set_mfa(f: &Fixture, app: &applications::Model, policy: AppMfaPolicy) {
    let mut row: applications::ActiveModel = app.clone().into();
    row.mfa_policy = Set(policy);
    row.update(&f.db).await.unwrap();
}

#[tokio::test]
async fn refresh_token_spans_consented_resources() {
    let f = Fixture::new().await;
    let (_, tokens) = f
        .web_tokens(
            "openid offline_access api://orders/Orders.Read",
            "ann@example.com",
        )
        .await;
    let rt = tokens["refresh_token"].as_str().unwrap().to_owned();

    // Not consented for this client yet: refused, and the token survives.
    let reply = f.refresh(&rt, Some(LEDGER)).await;
    assert_eq!(
        error(&reply),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    consent_to_ledger(&f).await;

    // MFA required by the other resource: a single-factor sign-in can't.
    set_mfa(&f, &f.ledger, AppMfaPolicy::Required).await;
    let reply = f.refresh(&rt, Some(LEDGER)).await;
    assert_eq!(
        error(&reply),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    set_mfa(&f, &f.ledger, AppMfaPolicy::Inherit).await;

    // Still one resource per request; OIDC scopes stay within the grant.
    for bad in [
        "api://ledger/Ledger.Read api://orders/Orders.Read",
        "email api://ledger/Ledger.Read",
        "api://ledger/Ledger.Write",
        // web-app registered no required permissions on the ledger.
        "api://ledger/.default",
    ] {
        let reply = f.refresh(&rt, Some(bad)).await;
        assert_eq!(
            error(&reply),
            (StatusCode::BAD_REQUEST, Some("invalid_scope")),
            "{bad}"
        );
    }

    let (rt, body) = redeem_ok(&f, &rt, &format!("openid {LEDGER}")).await;
    assert_eq!(body["scope"], format!("{LEDGER} openid"));
    assert!(body["id_token"].is_string());

    // The rotated token keeps the family's original grant.
    let (rt, body) = redeem_ok(&f, &rt, "api://orders/.default").await;
    assert_eq!(body["scope"], "api://orders/Orders.Read");
    let at = f
        .verify_jwt(body["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["scp"], "Orders.Read");
    let (status, body) = f.refresh(&rt, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["scope"],
        "api://orders/Orders.Read openid offline_access"
    );
    let rt = body["refresh_token"].as_str().unwrap().to_owned();

    // Withdrawing the ledger consent (as `DELETE …/consents/{id}` does)
    // revokes its tokens; the orders family lives on but can't reach the
    // ledger any more.
    let grant = consent_grants::Entity::find()
        .filter(consent_grants::Column::ResourceApplicationId.eq(f.ledger.id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    consent_grants::Entity::delete_by_id(grant.id)
        .exec(&f.db)
        .await
        .unwrap();
    refresh::revoke_grant(&f.db, f.tenant.id, f.web.id, f.ledger.id, Some(f.user.id))
        .await
        .unwrap();
    let live = opaque_access_tokens::Entity::find()
        .filter(opaque_access_tokens::Column::ResourceApplicationId.eq(f.ledger.id))
        .filter(opaque_access_tokens::Column::RevokedAt.is_null())
        .all(&f.db)
        .await
        .unwrap();
    assert!(live.is_empty(), "the ledger access token is revoked");
    let reply = f.refresh(&rt, Some(LEDGER)).await;
    assert_eq!(
        error(&reply),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    redeem_ok(&f, &rt, "api://orders/Orders.Read").await;
}

#[tokio::test]
async fn admin_consent_and_other_tenants() {
    let f = Fixture::new().await;
    let (_, tokens) = f
        .web_tokens("openid offline_access", "ann@example.com")
        .await;
    let rt = tokens["refresh_token"].as_str().unwrap().to_owned();

    // A resource of another tenant with the same identifier URI is never
    // found from this tenant's host.
    let other = directory::create_tenant(
        &f.db,
        &f.config,
        NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let billing = add_app(
        &f.db,
        other.id,
        "billing",
        ClientType::Confidential,
        Some("api://billing"),
        AccessTokenFormat::Jwt,
        SigningAlg::Rs256,
    )
    .await;
    add_scope(&f.db, &billing, "Billing.Read", false).await;
    let reply = f.refresh(&rt, Some("api://billing/Billing.Read")).await;
    assert_eq!(
        error(&reply),
        (StatusCode::BAD_REQUEST, Some("invalid_scope"))
    );

    // An admin-only scope needs the tenant-wide admin grant; with it, a
    // token granted without any resource reaches it.
    let manage = "api://orders/Orders.Manage";
    consent::store_grant(
        &f.db,
        f.tenant.id,
        f.web.id,
        f.orders.id,
        Some(f.user.id),
        &["Orders.Read".to_owned()],
    )
    .await
    .unwrap();
    let reply = f.refresh(&rt, Some(manage)).await;
    assert_eq!(
        error(&reply),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let values = ["Orders.Manage".to_owned()];
    consent::store_grant(&f.db, f.tenant.id, f.web.id, f.orders.id, None, &values)
        .await
        .unwrap();
    let (_, body) = redeem_ok(&f, &rt, manage).await;
    let at = f
        .verify_jwt(body["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["scp"], "Orders.Manage");
    assert_eq!(at["roles"], serde_json::json!(["Orders.Approver"]));
}
