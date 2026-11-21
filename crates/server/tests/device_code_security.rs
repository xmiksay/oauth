// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Device authorization grant: opt-in, client binding, code entry hardening
//! (CSRF, rate limit, tenant isolation) and the management API flag.
mod common;

use axum::http::{Method, StatusCode, header};
use common::{
    ORIGIN, at,
    device::{approve_as, enable, enter, poll, rows, start},
    flow::Fixture,
    mgmt::{app_admin_token, app_by_client_id, audited, audited_any, call},
};
use entity::{refresh_tokens, sessions};
use oauth_server::{
    authn::rate_limit,
    directory::{self, NewTenant},
};
use sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait};
use serde_json::json;

#[tokio::test]
async fn only_opted_in_clients_may_use_the_grant() {
    let f = Fixture::new().await;
    let (status, body) = start(&f, &f.spa, None, "openid").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unauthorized_client");
    let (_, body) = poll(&f, &f.spa, None, "whatever").await;
    assert_eq!(body["error"], "unauthorized_client");

    enable(&f, &f.web).await;
    let (status, body) = start(&f, &f.web, None, "openid").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "confidential needs its secret"
    );
    assert_eq!(body["error"], "invalid_client");
    for bad in ["", "openid api://nowhere/x", "api://orders/Nope"] {
        let (status, body) = start(&f, &f.web, Some(&f.web_secret), bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(body["error"], "invalid_scope", "{bad}");
    }

    // Opting out later stops both sides of a request already issued.
    let (_, start) = start(&f, &f.web, Some(&f.web_secret), "openid").await;
    f.db.execute_unprepared("UPDATE applications SET device_code_enabled = false")
        .await
        .unwrap();
    let mut browser = f.browser();
    let (status, body) = enter(&mut browser, start["user_code"].as_str().unwrap()).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_code"))
    );
    let device_code = start["device_code"].as_str().unwrap();
    let (_, body) = poll(&f, &f.web, Some(&f.web_secret), device_code).await;
    assert_eq!(body["error"], "unauthorized_client");
}

#[tokio::test]
async fn device_code_is_bound_to_its_client() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    enable(&f, &f.web).await;
    let (_, start) = start(&f, &f.spa, None, "openid").await;
    let device_code = start["device_code"].as_str().unwrap();
    approve_as(
        &f,
        start["user_code"].as_str().unwrap(),
        "ann@example.com",
        true,
    )
    .await;
    let (status, body) = poll(&f, &f.web, Some(&f.web_secret), device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    let form = [
        ("grant_type", common::device::GRANT),
        ("client_id", "spa-app"),
    ];
    let (_, _, body) = f.post_form("/oauth2/token", &form, None).await;
    assert_eq!(body["error"], "invalid_request");
    // The rightful client still gets its tokens.
    let (status, body) = poll(&f, &f.spa, None, device_code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn code_entry_is_csrf_checked_and_rate_limited() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let mut browser = f.browser();
    let (status, _, body) = browser
        .post_json(
            "/api/authn/device",
            &json!({ "user_code": "BCDF-GHJK" }),
            "https://evil.example",
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "csrf_rejected");

    for bad in ["BCDF-GHJK", "not a code", ""] {
        let (status, body) = enter(&mut browser, bad).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{bad}");
        assert_eq!(body["error"], "invalid_code");
    }
    for _ in 3..rate_limit::USER_CODE_PER_IP.max {
        enter(&mut browser, "BCDF-GHJK").await;
    }
    // Over the limit even the right code is refused.
    let (_, start) = start(&f, &f.spa, None, "openid").await;
    let (status, body) = enter(&mut browser, start["user_code"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
}

#[tokio::test]
async fn wrong_codes_are_capped_per_tenant_across_addresses() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (key, misses) = (rate_limit::USER_CODE_MISS_KEY, rate_limit::USER_CODE_MISSES);
    // Wrong guesses from many other addresses, one short of the cap.
    for _ in 1..misses.max {
        let hit = rate_limit::hit(&f.db, f.tenant.id, key, misses, chrono::Utc::now()).await;
        assert!(hit.unwrap().is_ok());
    }
    // Right codes don't count towards it.
    let mut browser = f.browser();
    for _ in 0..2 {
        let (_, started) = start(&f, &f.spa, None, "openid").await;
        let (status, body) = enter(&mut browser, started["user_code"].as_str().unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    // The last miss fills it; from then on even a right code is refused.
    let (status, _) = enter(&mut browser, "BCDF-GHJK").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, started) = start(&f, &f.spa, None, "openid").await;
    let (status, body) = enter(&mut f.browser(), started["user_code"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "rate_limited");
}

#[tokio::test]
async fn concurrent_polls_redeem_once() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    for round in 0..3_usize {
        let (_, started) = start(&f, &f.spa, None, "openid offline_access").await;
        let user_code = started["user_code"].as_str().unwrap();
        approve_as(&f, user_code, "ann@example.com", true).await;
        let device_code = started["device_code"].as_str().unwrap();
        let sessions_before = sessions::Entity::find().count(&f.db).await.unwrap();
        let (a, b, c, d) = tokio::join!(
            poll(&f, &f.spa, None, device_code),
            poll(&f, &f.spa, None, device_code),
            poll(&f, &f.spa, None, device_code),
            poll(&f, &f.spa, None, device_code),
        );
        let all = [a, b, c, d];
        let won: Vec<_> = all.iter().filter(|(s, _)| *s == StatusCode::OK).collect();
        assert_eq!(won.len(), 1, "round {round}: {all:?}");
        assert!(won[0].1["refresh_token"].is_string(), "round {round}");
        for (status, body) in all.iter().filter(|(s, _)| *s != StatusCode::OK) {
            assert_eq!(
                (*status, body["error"].as_str()),
                (StatusCode::BAD_REQUEST, Some("invalid_grant")),
                "round {round}"
            );
        }
        let redeemed = audited_any(&f.db, "device_code.redeem").await;
        assert_eq!(redeemed.len(), round + 1, "round {round}");
        let sessions_after = sessions::Entity::find().count(&f.db).await.unwrap();
        // Only the winner made the device a session.
        assert_eq!(sessions_after, sessions_before + 1, "round {round}");
        let issued = refresh_tokens::Entity::find().count(&f.db).await.unwrap();
        assert_eq!(issued, u64::try_from(round + 1).unwrap(), "round {round}");
    }
}

#[tokio::test]
async fn device_code_requests_are_rate_limited() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let max = rate_limit::DEVICE_AUTHORIZE_PER_IP.max;
    for _ in 0..max {
        let (status, body) = start(&f, &f.spa, None, "openid").await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let form = [("client_id", "spa-app"), ("scope", "openid")];
    let (status, headers, body) = f.post_form("/oauth2/devicecode", &form, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "rate_limited");
    let retry_after: u64 = headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry_after > 0);
    // Refused before anything is stored.
    assert_eq!(rows(&f).await.len(), usize::try_from(max).unwrap());
}

#[tokio::test]
async fn a_code_is_decided_once_and_only_in_its_tenant() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let new = NewTenant {
        slug: "fabrikam",
        display_name: "Fabrikam",
    };
    directory::create_tenant(&f.db, &f.config, new)
        .await
        .unwrap();
    let (_, start) = start(&f, &f.spa, None, "openid").await;
    let user_code = start["user_code"].as_str().unwrap();

    let mut browser = f.browser();
    let (status, _, body) = browser
        .post_json(
            &at("fabrikam", "/api/authn/device"),
            &json!({ "user_code": user_code }),
            &at("fabrikam", ""),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let url = approve_as(&f, user_code, "ann@example.com", true).await;
    assert_eq!(url, format!("{ORIGIN}/device?result=approved"));
    let (status, body) = enter(&mut f.browser(), user_code).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn management_api_toggles_the_flag() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}", f.spa.id);
    let (status, app) = call(&f.app, Method::GET, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(app["device_code_enabled"], false);
    let body = json!({ "device_code_enabled": true });
    let (status, app) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{app}");
    assert_eq!(app["device_code_enabled"], true);
    let events = audited(&f.db, "application.update", f.spa.id).await;
    assert_eq!(events[0]["fields"], json!(["device_code_enabled"]));
    let (status, started) = start(&f, &f.spa, None, "openid").await;
    assert_eq!(status, StatusCode::OK, "{started}");

    // Built-in apps never take it.
    let builtin = app_by_client_id(&f.db, f.tenant.id, "my-account").await;
    let path = format!("/api/v1/applications/{}", builtin.id);
    let (status, err) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
}
