// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Device authorization grant (RFC 8628) end to end: device code request,
//! code entry, sign-in, confirmation and polling.
mod common;

use axum::http::StatusCode;
use common::{
    ORIGIN,
    device::{approve_as, decide, enable, enter_tx, forget_last_poll, poll, rows, sign_in, start},
    flow::Fixture,
    mgmt::audited_any,
};
use entity::{enums::DeviceStatus, sessions};
use oauth_server::jobs::sweeper;
use sea_orm::{ConnectionTrait, EntityTrait};
use serde_json::Value;
use uuid::Uuid;

const EMAIL: &str = "ann@example.com";
const SCOPE: &str = "openid offline_access api://orders/Orders.Read";

#[tokio::test]
async fn discovery_advertises_the_device_grant() {
    let f = Fixture::new().await;
    let (status, body) = common::get(&f.app, "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        doc["device_authorization_endpoint"],
        format!("{ORIGIN}/oauth2/devicecode")
    );
    let grants = doc["grant_types_supported"].as_array().unwrap();
    assert!(grants.contains(&Value::from(common::device::GRANT)));
}

#[tokio::test]
async fn approved_device_gets_tokens_once_with_its_own_session() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (status, start) = start(&f, &f.spa, None, SCOPE).await;
    assert_eq!(status, StatusCode::OK, "{start}");
    let user_code = start["user_code"].as_str().unwrap();
    let device_code = start["device_code"].as_str().unwrap();
    assert_eq!(user_code.len(), 9);
    assert_eq!(start["verification_uri"], format!("{ORIGIN}/device"));
    assert_eq!(
        start["verification_uri_complete"],
        format!("{ORIGIN}/device?user_code={user_code}")
    );
    assert_eq!(start["expires_in"], 900);
    assert_eq!(start["interval"], 5);
    // Only hashes are stored.
    let row = &rows(&f).await[0];
    assert_ne!(row.device_code_hash, device_code.as_bytes());
    assert_eq!(row.scopes, ["openid", "offline_access", "Orders.Read"]);

    // Polling before the user acts; too fast → slow_down, interval + 5 s.
    let (status, body) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");
    let (_, body) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(body["error"], "slow_down");
    assert_eq!(rows(&f).await[0].interval_secs, 10);

    // The user types the code in another case, without the dash.
    let typed = user_code.replace('-', "").to_lowercase();
    let mut browser = f.browser();
    let tx = enter_tx(&mut browser, &typed).await;
    let (status, _, body) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK);
    let view: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (view["step"].as_str(), &view["device"]),
        (Some("password"), &Value::Bool(true))
    );
    assert_eq!(view["client"]["client_id"], "spa-app");
    let view = sign_in(&mut browser, &tx, EMAIL).await;
    assert_eq!(view["consent"]["scopes"][0]["value"], "Orders.Read");
    let url = decide(&mut browser, &tx, &view, true).await;
    assert_eq!(url, format!("{ORIGIN}/device?result=approved"));
    assert!(browser.has_session(), "the browser signed in for real");
    let row = &rows(&f).await[0];
    assert_eq!(row.status, DeviceStatus::Approved);
    assert_eq!(row.user_id, Some(f.user.id));
    assert_eq!(row.amr, ["pwd"]);

    let (status, tokens) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(tokens["refresh_token"].is_string() && tokens["id_token"].is_string());
    assert_eq!(
        tokens["scope"],
        "api://orders/Orders.Read openid offline_access"
    );
    let claims = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(claims["oid"], f.user.id.to_string());
    assert_eq!(claims["scp"], "Orders.Read");
    assert_eq!(claims["client_id"], "spa-app");
    // The device has a session of its own, separate from the browser's.
    let sid = Uuid::parse_str(claims["sid"].as_str().unwrap()).unwrap();
    let all = sessions::Entity::find().all(&f.db).await.unwrap();
    assert_eq!(all.len(), 2);
    let device_session = all.iter().find(|s| s.id == sid).unwrap();
    assert_eq!(device_session.user_id, f.user.id);
    assert_eq!(device_session.amr, ["pwd"]);

    // Single use.
    let (status, body) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    // The refresh token works like any other.
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", "spa-app"),
    ];
    let (status, _, body) = f.post_form("/oauth2/token", &form, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let approved = audited_any(&f.db, "device_code.approve").await;
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0]["device_authorization_id"], row.id.to_string());
    let redeemed = audited_any(&f.db, "device_code.redeem").await;
    assert_eq!(redeemed[0]["session_id"], sid.to_string());
}

#[tokio::test]
async fn declined_request_answers_access_denied() {
    let f = Fixture::new().await;
    enable(&f, &f.web).await;
    let (_, start) = start(&f, &f.web, Some(&f.web_secret), "openid").await;
    let url = approve_as(&f, start["user_code"].as_str().unwrap(), EMAIL, false).await;
    assert_eq!(url, format!("{ORIGIN}/device?error=access_denied"));
    let device_code = start["device_code"].as_str().unwrap();
    let (status, body) = poll(&f, &f.web, Some(&f.web_secret), device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(rows(&f).await[0].status, DeviceStatus::Denied);
    let denied = audited_any(&f.db, "device_code.deny").await;
    assert_eq!(denied[0]["reason"], "declined");
}

#[tokio::test]
async fn signed_in_browser_still_confirms_even_when_consented() {
    let f = Fixture::new().await;
    enable(&f, &f.web).await;
    // A browser session plus an existing grant of Orders.Read to web-app.
    let (mut browser, _) = f.web_tokens("openid api://orders/Orders.Read", EMAIL).await;
    let (_, start) = start(
        &f,
        &f.web,
        Some(&f.web_secret),
        "openid api://orders/Orders.Read",
    )
    .await;
    let tx = enter_tx(&mut browser, start["user_code"].as_str().unwrap()).await;
    let (_, _, body) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    let view: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["step"], "consent", "{view}");
    // Already consented, yet listed: the user sees what the device gets.
    assert_eq!(view["consent"]["scopes"][0]["value"], "Orders.Read");
    let url = decide(&mut browser, &tx, &view, true).await;
    assert_eq!(url, format!("{ORIGIN}/device?result=approved"));
    let device_code = start["device_code"].as_str().unwrap();
    let (status, tokens) = poll(&f, &f.web, Some(&f.web_secret), device_code).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
}

#[tokio::test]
async fn oidc_only_request_confirms_without_resource() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (_, start) = start(&f, &f.spa, None, "openid profile").await;
    let mut browser = f.browser();
    let tx = enter_tx(&mut browser, start["user_code"].as_str().unwrap()).await;
    let view = sign_in(&mut browser, &tx, EMAIL).await;
    assert!(view["consent"].is_null(), "{view}");
    let url = decide(&mut browser, &tx, &view, true).await;
    assert_eq!(url, format!("{ORIGIN}/device?result=approved"));
    let device_code = start["device_code"].as_str().unwrap();
    let (status, tokens) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(tokens.get("refresh_token").is_none());
}

#[tokio::test]
async fn admin_consent_scopes_deny_the_device() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (_, start) = start(&f, &f.spa, None, "openid api://orders/Orders.Manage").await;
    let mut browser = f.browser();
    let tx = enter_tx(&mut browser, start["user_code"].as_str().unwrap()).await;
    let (status, body) = browser
        .step(
            &tx,
            "password",
            serde_json::json!({ "email": EMAIL, "password": common::flow::PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["redirect"],
        format!("{ORIGIN}/device?error=consent_required")
    );
    let device_code = start["device_code"].as_str().unwrap();
    let (_, body) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(body["error"], "access_denied");
    let denied = audited_any(&f.db, "device_code.deny").await;
    assert_eq!(denied[0]["reason"], "admin_consent_required");
}

#[tokio::test]
async fn expired_request_and_sweeper() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (_, start) = start(&f, &f.spa, None, "openid").await;
    f.db.execute_unprepared(
        "UPDATE device_authorizations SET expires_at = now() - interval '1 second'",
    )
    .await
    .unwrap();
    let device_code = start["device_code"].as_str().unwrap();
    let (status, body) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "expired_token");
    let mut browser = f.browser();
    let (status, body) =
        common::device::enter(&mut browser, start["user_code"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_code");
    let report = sweeper::run_once(&f.db).await.unwrap().unwrap();
    assert!(report.contains(&("device_authorizations", 1)), "{report:?}");
    assert!(rows(&f).await.is_empty());
}

#[tokio::test]
async fn request_expiring_during_sign_in_is_not_approved() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (_, start) = start(&f, &f.spa, None, "openid").await;
    let mut browser = f.browser();
    let tx = enter_tx(&mut browser, start["user_code"].as_str().unwrap()).await;
    let view = sign_in(&mut browser, &tx, EMAIL).await;
    f.db.execute_unprepared(
        "UPDATE device_authorizations SET expires_at = now() - interval '1 second'",
    )
    .await
    .unwrap();
    let url = decide(&mut browser, &tx, &view, true).await;
    assert_eq!(url, format!("{ORIGIN}/device?error=expired_token"));
    assert_eq!(rows(&f).await[0].status, DeviceStatus::Pending);
    assert!(audited_any(&f.db, "device_code.approve").await.is_empty());
}

#[tokio::test]
async fn polling_respects_the_grown_interval() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (_, start) = start(&f, &f.spa, None, "openid").await;
    let device_code = start["device_code"].as_str().unwrap();
    for expected in [5, 10, 15] {
        let (_, body) = poll(&f, &f.spa, None, device_code).await;
        assert!(
            ["authorization_pending", "slow_down"].contains(&body["error"].as_str().unwrap()),
            "{body}"
        );
        assert_eq!(rows(&f).await[0].interval_secs, expected);
    }
    // A poll on time keeps the interval.
    forget_last_poll(&f).await;
    let (_, body) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(body["error"], "authorization_pending");
    assert_eq!(rows(&f).await[0].interval_secs, 15);
}
