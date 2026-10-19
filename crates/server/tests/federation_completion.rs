//! Completing an upstream sign-in that waited at a later step (MFA): the
//! IdP configuration it was verified against must still hold, and the
//! completing transaction locks the IdP row before the login transaction
//! (the order a repoint uses), so the two can't deadlock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{
    browser::{Browser, current_totp},
    federation::{Fed, is_login_page},
    mgmt::audited_any,
};
use entity::{sessions, user_totp, users};
use oauth_server::directory;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, Statement,
    TransactionTrait, sea_query::Expr,
};
use serde_json::json;

/// A JIT user with TOTP, and their next federated sign-in parked at `mfa`.
async fn at_mfa(fed: &Fed, idp: &str) -> (users::Model, Browser, String) {
    let user =
        match directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, "pat@upstream.example")
            .await
            .unwrap()
        {
            Some(user) => user,
            None => {
                fed.sign_in(&mut fed.f.browser(), idp).await;
                let user = directory::find_user_by_email(
                    &fed.f.db,
                    fed.f.tenant.id,
                    "pat@upstream.example",
                )
                .await
                .unwrap()
                .unwrap();
                fed.f.enroll_totp(&user).await;
                user
            }
        };
    // Each test submits one code per transaction; allow it again.
    user_totp::Entity::update_many()
        .col_expr(
            user_totp::Column::LastUsedStep,
            Expr::value(Option::<i64>::None),
        )
        .exec(&fed.f.db)
        .await
        .unwrap();
    let mut browser = fed.f.browser();
    let (tx, location) = fed.sign_in(&mut browser, idp).await;
    assert!(is_login_page(&location, &tx), "{location}");
    (user, browser, tx)
}

async fn sessions_of(fed: &Fed, user: &users::Model) -> u64 {
    sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(user.id))
        .count(&fed.f.db)
        .await
        .unwrap()
}

async fn last_reason(fed: &Fed) -> String {
    let events = audited_any(&fed.f.db, "sign_in").await;
    events.last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn a_provider_changed_while_waiting_at_mfa_ends_the_sign_in() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    for (change, reason) in [
        (json!({ "enabled": false }), "idp_disabled"),
        (json!({ "client_id": "moved" }), "idp_repointed"),
    ] {
        let (user, mut browser, tx) = at_mfa(&fed, &idp).await;
        let before = sessions_of(&fed, &user).await;
        fed.patch_idp(&idp, change.clone()).await;
        let (status, resp) = browser
            .step(&tx, "totp", json!({ "code": current_totp() }))
            .await;
        assert_eq!(
            (status, resp["error"].as_str()),
            (StatusCode::BAD_GATEWAY, Some("upstream_failed")),
            "{change}"
        );
        assert_eq!(sessions_of(&fed, &user).await, before, "no session");
        assert_eq!(last_reason(&fed).await, reason);
        let (status, _, _) = browser.get(&format!("/api/authn/tx/{tx}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the transaction is dead");
        // Re-enable for the next case (which is the last: it unlinks).
        fed.patch_idp(&idp, json!({ "enabled": true })).await;
    }
}

#[tokio::test]
async fn completion_locks_the_provider_before_the_transaction() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let (_, mut browser, tx) = at_mfa(&fed, &idp).await;
    // Hold the provider the way a repoint does, then touch the login
    // transaction while the TOTP submission is waiting on the provider.
    let repoint = fed.f.db.begin().await.unwrap();
    repoint
        .execute_raw(Statement::from_sql_and_values(
            repoint.get_database_backend(),
            "SELECT id FROM identity_providers WHERE id = $1::uuid FOR UPDATE",
            [idp.clone().into()],
        ))
        .await
        .unwrap();
    let code = current_totp();
    let tx_id = tx.clone();
    let submit =
        tokio::spawn(async move { browser.step(&tx_id, "totp", json!({ "code": code })).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let touched = tokio::time::timeout(
        Duration::from_secs(10),
        repoint.execute_raw(Statement::from_sql_and_values(
            repoint.get_database_backend(),
            "UPDATE login_transactions SET expires_at = expires_at WHERE id = $1::uuid",
            [tx.clone().into()],
        )),
    )
    .await
    .expect("the transaction row is not held by the waiting sign-in");
    assert!(touched.is_ok(), "{touched:?}");
    repoint.commit().await.unwrap();
    let (status, resp) = submit.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(resp["redirect"].is_string(), "{resp}");
}
