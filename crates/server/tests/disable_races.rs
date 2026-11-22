// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A user disabled (or deleted) while a sign-in completion or a token grant
//! waits on the user lock (`backchannel::lock_user`): the waiter re-reads
//! the user under the lock and issues nothing.
mod common;

use axum::http::StatusCode;
use common::{
    ORIGIN,
    backchannel::wait_for_lock_waiter,
    browser::authorize_url,
    device::{enable, enter, rows, start},
    flow::{Fixture, PASSWORD, WEB_CB},
};
use entity::{
    app_role_assignments, applications, authorization_codes, enums::DeviceStatus, sessions, users,
};
use oauth_server::directory;
use sea_orm::{
    ColumnTrait, DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect,
    TransactionTrait, sea_query::Expr,
};

const SCOPE: &str = "openid offline_access";
const EMAIL: &str = "ann@example.com";

/// An admin action as it starts: the user row locked `FOR UPDATE`.
async fn admin_holding_user(f: &Fixture) -> DatabaseTransaction {
    let txn = f.db.begin().await.unwrap();
    users::Entity::find_by_id(f.user.id)
        .lock_exclusive()
        .one(&txn)
        .await
        .unwrap()
        .unwrap();
    txn
}

/// Once the other side waits on the lock: disable the user and, when
/// `revoke`, end their sessions and tokens too (what `PATCH disabled`
/// does). Without `revoke` only the re-check under the lock can refuse.
async fn admin_disables(f: &Fixture, txn: DatabaseTransaction, revoke: bool) {
    wait_for_lock_waiter(&f.db).await;
    users::Entity::update_many()
        .col_expr(users::Column::Disabled, Expr::value(true))
        .filter(users::Column::Id.eq(f.user.id))
        .exec(&txn)
        .await
        .unwrap();
    if revoke {
        directory::revoke_credentials(&txn, &f.config.master_key, f.tenant.id, f.user.id, None)
            .await
            .unwrap();
    }
    txn.commit().await.unwrap();
}

async fn count_for_user<E>(f: &Fixture, column: E::Column) -> u64
where
    E: EntityTrait,
    E::Model: Sync,
{
    E::find()
        .filter(column.eq(f.user.id))
        .count(&f.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn login_completion_refuses_a_user_disabled_while_it_waited() {
    let f = Fixture::new().await;
    let (mut browser, _) = f.web_tokens(SCOPE, EMAIL).await;
    let codes_before =
        count_for_user::<authorization_codes::Entity>(&f, authorization_codes::Column::UserId)
            .await;
    let url = authorize_url("web-app", WEB_CB, SCOPE, &[("prompt", "login")]);
    let tx = browser.authorize(&url).await.unwrap();
    let (status, _, _) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK);
    let txn = admin_holding_user(&f).await;
    let body = serde_json::json!({ "email": EMAIL, "password": PASSWORD });
    let ((status, resp), ()) = tokio::join!(
        browser.step(&tx, "password", body),
        admin_disables(&f, txn, true)
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["error"], "account_disabled");
    assert_eq!(
        count_for_user::<sessions::Entity>(&f, sessions::Column::UserId).await,
        0
    );
    assert_eq!(
        count_for_user::<authorization_codes::Entity>(&f, authorization_codes::Column::UserId)
            .await,
        codes_before
    );
}

#[tokio::test]
async fn code_redemption_refuses_a_user_disabled_while_it_waited() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, SCOPE, &[]);
    let code = browser.login_for_code(&url, EMAIL).await;
    let txn = admin_holding_user(&f).await;
    let redeem = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB);
    let (redeemed, ()) = tokio::join!(redeem, admin_disables(&f, txn, false));
    assert_eq!(redeemed.0, StatusCode::BAD_REQUEST, "{:?}", redeemed.1);
    assert_eq!(redeemed.1["error"], "invalid_grant");
    assert_eq!(
        redeemed.1["error_description"],
        "the user is disabled or no longer exists"
    );
}

#[tokio::test]
async fn refresh_refuses_a_user_disabled_while_it_waited() {
    let f = Fixture::new().await;
    let (_browser, tokens) = f.web_tokens(SCOPE, EMAIL).await;
    let rt = tokens["refresh_token"].as_str().unwrap();
    let txn = admin_holding_user(&f).await;
    let (refreshed, ()) = tokio::join!(f.refresh(rt, None), admin_disables(&f, txn, false));
    assert_eq!(refreshed.0, StatusCode::BAD_REQUEST, "{:?}", refreshed.1);
    assert_eq!(refreshed.1["error"], "invalid_grant");
    assert_eq!(
        refreshed.1["error_description"],
        "the user is disabled or no longer exists"
    );
}

/// Denying a device request writes the user into its row: it takes the
/// user lock first, so a deletion meanwhile leaves the request untouched
/// instead of failing the row's FK.
#[tokio::test]
async fn device_deny_waits_for_a_user_deletion() {
    let f = Fixture::new().await;
    let (mut browser, _) = f.web_tokens("openid", EMAIL).await;
    enable(&f, &f.spa).await;
    applications::Entity::update_many()
        .col_expr(applications::Column::AssignmentRequired, Expr::value(true))
        .filter(applications::Column::Id.eq(f.orders.id))
        .exec(&f.db)
        .await
        .unwrap();
    app_role_assignments::Entity::delete_many()
        .filter(app_role_assignments::Column::ResourceApplicationId.eq(f.orders.id))
        .exec(&f.db)
        .await
        .unwrap();
    let (_, started) = start(&f, &f.spa, None, "openid api://orders/Orders.Read").await;
    let user_code = started["user_code"].as_str().unwrap();
    let txn = admin_holding_user(&f).await;
    let ((status, body), ()) = tokio::join!(enter(&mut browser, user_code), async {
        wait_for_lock_waiter(&f.db).await;
        users::Entity::delete_by_id(f.user.id)
            .exec(&txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    });
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["redirect"],
        format!("{ORIGIN}/device?error=not_assigned")
    );
    assert_eq!(rows(&f).await[0].status, DeviceStatus::Pending);
}
