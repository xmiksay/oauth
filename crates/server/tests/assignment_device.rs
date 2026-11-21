// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `assignment_required` on the device authorization grant: code entry,
//! sign-in and redemption refuse an unassigned user.
mod common;

use axum::http::StatusCode;
use common::{
    ORIGIN,
    device::{approve_as, enable, enter, poll, rows, sign_in, start},
    flow::Fixture,
    mgmt::audited_any,
};
use entity::{app_role_assignments, applications, enums::DeviceStatus};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr};

const EMAIL: &str = "ann@example.com";
const ORDERS: &str = "openid api://orders/Orders.Read";

async fn require(f: &Fixture, app: &applications::Model) {
    applications::Entity::update_many()
        .col_expr(applications::Column::AssignmentRequired, Expr::value(true))
        .filter(applications::Column::Id.eq(app.id))
        .exec(&f.db)
        .await
        .unwrap();
}

async fn assert_denied(f: &Fixture, app: &applications::Model, device_code: &str) {
    assert_eq!(rows(f).await[0].status, DeviceStatus::Denied);
    let denied = audited_any(&f.db, "device_code.deny").await;
    assert_eq!(denied[0]["reason"], "not_assigned");
    let (_, body) = poll(f, app, None, device_code).await;
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn an_unassigned_user_is_refused_after_sign_in() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    require(&f, &f.spa).await;
    let (_, start) = start(&f, &f.spa, None, "openid").await;
    let mut browser = f.browser();
    let (status, body) = enter(&mut browser, start["user_code"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tx = body["redirect"]
        .as_str()
        .unwrap()
        .strip_prefix(&format!("{ORIGIN}/login?tx="))
        .unwrap()
        .to_owned();
    let view = sign_in(&mut browser, &tx, EMAIL).await;
    assert_eq!(
        view["redirect"],
        format!("{ORIGIN}/device?error=not_assigned")
    );
    assert!(!browser.has_session());
    assert_denied(&f, &f.spa, start["device_code"].as_str().unwrap()).await;
}

#[tokio::test]
async fn a_signed_in_unassigned_user_is_refused_at_code_entry() {
    let f = Fixture::new().await;
    let (mut browser, _) = f.web_tokens("openid", EMAIL).await;
    enable(&f, &f.spa).await;
    require(&f, &f.orders).await;
    app_role_assignments::Entity::delete_many()
        .filter(app_role_assignments::Column::ResourceApplicationId.eq(f.orders.id))
        .exec(&f.db)
        .await
        .unwrap();
    let (_, start) = start(&f, &f.spa, None, ORDERS).await;
    let (status, body) = enter(&mut browser, start["user_code"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["redirect"],
        format!("{ORIGIN}/device?error=not_assigned")
    );
    assert_denied(&f, &f.spa, start["device_code"].as_str().unwrap()).await;
}

#[tokio::test]
async fn an_assignment_removed_before_redemption_fails_the_poll() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    // `orders` gives the user's group Orders.Approver.
    require(&f, &f.orders).await;
    let (_, start) = start(&f, &f.spa, None, ORDERS).await;
    let url = approve_as(&f, start["user_code"].as_str().unwrap(), EMAIL, true).await;
    assert_eq!(url, format!("{ORIGIN}/device?result=approved"));
    app_role_assignments::Entity::delete_many()
        .filter(app_role_assignments::Column::ResourceApplicationId.eq(f.orders.id))
        .exec(&f.db)
        .await
        .unwrap();
    let (status, body) = poll(&f, &f.spa, None, start["device_code"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "{body}");
}
