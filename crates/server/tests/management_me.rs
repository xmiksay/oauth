// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Self-service (`me/…`): MFA enrollment, password, sessions, consents.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    browser::authorize_url,
    flow::{Fixture, PASSWORD, WEB_CB},
    mgmt::{base32_decode, call, mint_user_token},
};
use entity::{audit_events, sessions};
use oauth_server::authn::totp;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::{Value, json};

const ME: &str = "/api/v1/me";

fn code_for(secret: &[u8]) -> String {
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    format!("{:06}", totp::hotp(secret, now / totp::STEP_SECS))
}

#[tokio::test]
async fn totp_enrollment_then_sign_in_requires_it() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let tok = Some(token.as_str());
    let path = |p: &str| format!("{ME}{p}");

    let (st, _) = call(
        &f.app,
        Method::POST,
        &path("/totp"),
        tok,
        Some(&json!({ "password": "wrong password!" })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, begun) = call(
        &f.app,
        Method::POST,
        &path("/totp"),
        tok,
        Some(&json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{begun}");
    let b32 = begun["secret"].as_str().unwrap();
    assert!(
        begun["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Contoso:ann%40example%2Ecom?secret=")
    );
    let secret = base32_decode(b32);
    assert_eq!(secret.len(), 20);

    // Pending: sign-in doesn't ask for it yet.
    let (_, me) = call(&f.app, Method::GET, ME, tok, None).await;
    assert_eq!(
        (
            me["mfa"]["totp"].as_bool(),
            me["mfa"]["totp_pending"].as_bool()
        ),
        (Some(false), Some(true))
    );
    let (st, _) = call(
        &f.app,
        Method::POST,
        &path("/totp/confirm"),
        tok,
        Some(&json!({ "code": "000000" })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, confirmed) = call(
        &f.app,
        Method::POST,
        &path("/totp/confirm"),
        tok,
        Some(&json!({ "code": code_for(&secret) })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{confirmed}");
    let codes: Vec<String> = confirmed["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    let (_, me) = call(&f.app, Method::GET, ME, tok, None).await;
    assert_eq!(
        (
            me["mfa"]["totp"].as_bool(),
            me["mfa"]["recovery_codes_remaining"].as_u64()
        ),
        (Some(true), Some(10))
    );
    let (st, _) = call(
        &f.app,
        Method::POST,
        &path("/totp"),
        tok,
        Some(&json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "re-enrolling would silently replace the factor"
    );
    // The storage layer itself refuses too (a racing enrollment that passed
    // the handler's check can't un-confirm the factor).
    let sealed = totp::seal_secret(&f.config.master_key, f.tenant.id, f.user.id, b"x").unwrap();
    assert!(
        !totp::store(&f.db, f.tenant.id, f.user.id, sealed, false)
            .await
            .unwrap()
    );
    let still = totp::confirmed(&f.db, f.tenant.id, f.user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        totp::open_secret(&f.config.master_key, &still)
            .unwrap()
            .as_slice()
            == secret.as_slice()
    );

    // Sign-in now stops at the second factor; a recovery code passes it.
    let mut browser = f.browser();
    let tx = browser
        .authorize(&authorize_url("web-app", WEB_CB, "openid", &[]))
        .await
        .unwrap();
    let (st, step) = browser
        .step(
            &tx,
            "password",
            json!({ "email": "ann@example.com", "password": PASSWORD }),
        )
        .await;
    assert_eq!(
        (st, step["step"].as_str()),
        (StatusCode::OK, Some("mfa")),
        "{step}"
    );
    let (st, done) = browser
        .step(&tx, "recovery", json!({ "code": codes[0].to_uppercase() }))
        .await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert!(done["redirect"].as_str().unwrap().contains("code="));

    // Regenerating replaces the codes (password required; the per-account
    // attempt budget is shared with sign-in, so wrong guesses are only
    // tried below).
    let (st, _) = call(
        &f.app,
        Method::POST,
        &path("/recovery-codes"),
        tok,
        Some(&json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, fresh) = call(
        &f.app,
        Method::POST,
        &path("/recovery-codes"),
        tok,
        Some(&json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !fresh["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str() == Some(codes[1].as_str()))
    );

    // Removal needs the password and turns the second step off again.
    let (st, _) = call(
        &f.app,
        Method::DELETE,
        &path("/totp"),
        tok,
        Some(&json!({ "password": "nope nope nope" })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = call(
        &f.app,
        Method::DELETE,
        &path("/totp"),
        tok,
        Some(&json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (_, me) = call(&f.app, Method::GET, ME, tok, None).await;
    assert_eq!(
        (
            me["mfa"]["totp"].as_bool(),
            me["mfa"]["recovery_codes_remaining"].as_u64()
        ),
        (Some(false), Some(0))
    );

    let events: Vec<String> = audit_events::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.event_type)
        .collect();
    for expected in [
        "user.mfa.totp_enroll",
        "user.mfa.recovery_codes_regenerate",
        "user.mfa.totp_remove",
    ] {
        assert!(
            events.iter().any(|e| e == expected),
            "{expected}: {events:?}"
        );
    }
    let details = serde_json::to_string(
        &audit_events::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .iter()
            .map(|e| e.details.clone())
            .collect::<Vec<Value>>(),
    )
    .unwrap();
    assert!(!details.contains(b32) && !details.contains(&codes[0]));
}

#[tokio::test]
async fn profile_password_sessions_and_consents() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let tok = Some(token.as_str());

    let (st, me) = call(
        &f.app,
        Method::PATCH,
        ME,
        tok,
        Some(&json!({ "display_name": "Ann Smith" })),
    )
    .await;
    assert_eq!(
        (st, me["display_name"].as_str()),
        (StatusCode::OK, Some("Ann Smith"))
    );
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        ME,
        tok,
        Some(&json!({ "email": "x@y.z" })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "only the display name is self-service"
    );

    // A user consent (web-app → orders) and its refresh token.
    let (_, tokens) = f
        .web_tokens(
            "openid offline_access api://orders/Orders.Read",
            "ann@example.com",
        )
        .await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    let (_, consents) = call(&f.app, Method::GET, &format!("{ME}/consents"), tok, None).await;
    let items = consents["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{consents}");
    assert_eq!(items[0]["client"]["client_id"], "web-app");
    assert_eq!(items[0]["scopes"], json!(["Orders.Read"]));
    let grant = format!("{ME}/consents/{}", items[0]["id"].as_str().unwrap());
    assert_eq!(
        call(&f.app, Method::DELETE, &grant, tok, None).await.0,
        StatusCode::NO_CONTENT
    );
    let (st, body) = f.refresh(&refresh, None).await;
    assert_eq!(
        (st, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &grant, tok, None).await.0,
        StatusCode::NOT_FOUND
    );

    // Sessions: list, revoke one (and the refresh tokens issued in it).
    let (_, tokens) = f
        .web_tokens("openid offline_access", "ann@example.com")
        .await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    let (_, list) = call(&f.app, Method::GET, &format!("{ME}/sessions"), tok, None).await;
    let items = list["items"].as_array().unwrap();
    // The token's own session (oldest) plus the two web sign-ins.
    assert_eq!(items.len(), 3, "{list}");
    let current: Vec<bool> = items.iter().map(|i| i["current"] == true).collect();
    assert_eq!(current, [false, false, true]);
    let newest = format!("{ME}/sessions/{}", items[0]["id"].as_str().unwrap());
    assert_eq!(
        call(&f.app, Method::DELETE, &newest, tok, None).await.0,
        StatusCode::NO_CONTENT
    );
    let (st, _) = f.refresh(&refresh, None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(
        call(&f.app, Method::DELETE, &newest, tok, None).await.0,
        StatusCode::NOT_FOUND
    );

    // Password change: current password required, then every OTHER session
    // ends — the caller's own survives, so the SPA keeps working.
    let change = |current: &str| json!({ "current_password": current, "new_password": "a brand new passphrase" });
    let path = format!("{ME}/change-password");
    assert_eq!(
        call(
            &f.app,
            Method::POST,
            &path,
            tok,
            Some(&change("wrong one!!!"))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&f.app, Method::POST, &path, tok, Some(&change(PASSWORD)))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let left = sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(left, 1);
    assert_eq!(
        call(&f.app, Method::GET, ME, tok, None).await.0,
        StatusCode::OK
    );
    // Signing out everywhere includes this session: its management token
    // is dead at once, JWT or not.
    let (st, _) = call(
        &f.app,
        Method::POST,
        &format!("{ME}/sessions/revoke-all"),
        tok,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        call(&f.app, Method::GET, ME, tok, None).await.0,
        StatusCode::UNAUTHORIZED
    );
}
