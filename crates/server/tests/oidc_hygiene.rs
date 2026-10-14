// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Session and token hygiene: consent merging, disabled users, password
//! changes, re-authentication, TOTP replay, JWT introspection.
mod common;

use axum::http::StatusCode;
use common::{
    browser::{authorize_url, current_totp, query_of},
    flow::{Fixture, PASSWORD, WEB_CB},
    seed::add_secret,
};
use entity::{consent_grants, sessions, users};
use oauth_server::directory;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
};
use serde_json::{Value, json};

async fn introspect(f: &Fixture, token: &str, client: &str, secret: &str) -> Value {
    let (status, _, body) = f
        .post_form(
            "/oauth2/introspect",
            &[("token", token)],
            Some((client, secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn consent_grants_are_merged() {
    let f = Fixture::new().await;
    f.web_tokens("api://orders/Orders.Read", "ann@example.com")
        .await;
    let mut browser = f.browser();
    let tx = browser
        .authorize(&authorize_url(
            "web-app",
            WEB_CB,
            "api://orders/Orders.Read api://orders/Orders.Write",
            &[],
        ))
        .await
        .unwrap();
    let (_, resp) = browser
        .step(
            &tx,
            "password",
            json!({ "email": "ann@example.com", "password": PASSWORD }),
        )
        .await;
    // Only the new scope is asked for.
    assert_eq!(
        resp["consent"]["scopes"],
        json!([{ "value": "Orders.Write", "description": "Orders.Write description" }])
    );
    let (status, _) = browser
        .step(
            &tx,
            "consent",
            json!({ "approve": true, "scopes": ["Orders.Write"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let grant = consent_grants::Entity::find()
        .filter(consent_grants::Column::UserId.eq(f.user.id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.scopes, ["Orders.Read", "Orders.Write"]);
}

#[tokio::test]
async fn disabled_user_tokens_stop_working() {
    let f = Fixture::new().await;
    let (_, tokens) = f
        .web_tokens("offline_access api://ledger/Ledger.Read", "ann@example.com")
        .await;
    let (_, jwt) = f
        .web_tokens("api://orders/Orders.Read", "ann@example.com")
        .await;
    let orders_secret = add_secret(&f.db, &f.orders).await;
    // JWT access tokens can be introspected by their resource.
    let body = introspect(
        &f,
        jwt["access_token"].as_str().unwrap(),
        "orders",
        &orders_secret,
    )
    .await;
    assert_eq!(
        (body["active"].as_bool(), body["scope"].as_str()),
        (Some(true), Some("Orders.Read"))
    );
    let body = introspect(
        &f,
        tokens["refresh_token"].as_str().unwrap(),
        "web-app",
        &f.web_secret,
    )
    .await;
    assert_eq!(body["scope"], "api://ledger/Ledger.Read offline_access");

    let mut user: users::ActiveModel = f.user.clone().into();
    user.disabled = Set(true);
    user.update(&f.db).await.unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        introspect(&f, access, "ledger", &f.ledger_secret).await,
        json!({ "active": false })
    );
    let body = introspect(
        &f,
        jwt["access_token"].as_str().unwrap(),
        "orders",
        &orders_secret,
    )
    .await;
    assert_eq!(body, json!({ "active": false }));
    let rt = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(
        introspect(&f, rt, "web-app", &f.web_secret).await,
        json!({ "active": false })
    );
    let (status, body) = f.refresh(rt, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn password_change_revokes_sessions_and_refresh_tokens() {
    let f = Fixture::new().await;
    let (mut browser, tokens) = f
        .web_tokens("offline_access api://ledger/Ledger.Read", "ann@example.com")
        .await;
    directory::set_password(
        &f.db,
        f.tenant.id,
        f.user.id,
        "an entirely new secret",
        false,
    )
    .await
    .unwrap();
    let (status, _) = f
        .refresh(tokens["refresh_token"].as_str().unwrap(), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let access = tokens["access_token"].as_str().unwrap();
    let body = introspect(&f, access, "ledger", &f.ledger_secret).await;
    assert_eq!(
        body,
        json!({ "active": false }),
        "opaque access token revoked"
    );
    let live = entity::opaque_access_tokens::Entity::find()
        .filter(entity::opaque_access_tokens::Column::RevokedAt.is_null())
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(live, 0);
    let url = authorize_url("web-app", WEB_CB, "openid", &[("prompt", "none")]);
    let redirect = browser.authorize(&url).await.unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "login_required");
}

#[tokio::test]
async fn reauthentication_replaces_the_previous_session() {
    let f = Fixture::new().await;
    let (mut browser, _) = f.web_tokens("openid", "ann@example.com").await;
    let url = authorize_url("web-app", WEB_CB, "openid", &[("prompt", "login")]);
    let tx = browser.authorize(&url).await.unwrap();
    browser.complete_login(&tx, "ann@example.com").await;
    let count = sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(count, 1, "the old session row is deleted");
}

#[tokio::test]
async fn totp_code_cannot_be_replayed() {
    let f = Fixture::new().await;
    f.enroll_totp(&f.user).await;
    let creds = json!({ "email": "ann@example.com", "password": PASSWORD });
    let code = current_totp();
    let mut first = f.browser();
    let tx = first
        .authorize(&authorize_url("web-app", WEB_CB, "openid", &[]))
        .await
        .unwrap();
    first.step(&tx, "password", creds.clone()).await;
    let (status, resp) = first.step(&tx, "totp", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let mut second = f.browser();
    let tx = second
        .authorize(&authorize_url("web-app", WEB_CB, "openid", &[]))
        .await
        .unwrap();
    second.step(&tx, "password", creds).await;
    let (status, resp) = second.step(&tx, "totp", json!({ "code": code })).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_code"))
    );
}
