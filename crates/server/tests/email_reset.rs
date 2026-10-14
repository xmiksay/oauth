// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Self-service password reset by email link.
mod common;

use axum::http::StatusCode;
use common::{
    ORIGIN, at,
    flow::{Fixture, PASSWORD},
    mail::{only_to, token_in},
};
use entity::{email_tokens, users};
use oauth_server::directory::{self, NewTenant, password};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, sea_query::Expr};
use serde_json::{Value, json};

const ANN: &str = "ann@example.com";
const NEW_PASSWORD: &str = "a brand new passphrase";

async fn request_reset(f: &Fixture, email: &str) -> (StatusCode, Value) {
    let (status, _, body) = f
        .browser()
        .post_json(
            "/api/authn/password-reset",
            &json!({ "email": email }),
            ORIGIN,
        )
        .await;
    (status, body)
}

async fn complete(f: &Fixture, token: &str, password: &str) -> (StatusCode, Value) {
    let body = json!({ "token": token, "new_password": password });
    let (status, _, body) = f
        .browser()
        .post_json("/api/authn/email/reset", &body, ORIGIN)
        .await;
    (status, body)
}

async fn password_is(f: &Fixture, id: uuid::Uuid, candidate: &str) -> bool {
    let user = users::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    password::verify(candidate, user.password_hash.as_deref().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn reset_sets_password_and_revokes_refresh_tokens() {
    let f = Fixture::with_email().await;
    let ann = f.verify(&f.user).await;
    let (_browser, tokens) = f.web_tokens("openid offline_access", ANN).await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    f.deliver().await; // the new-sign-in notice
    // A must-change flag is cleared by the reset.
    let mut row: users::ActiveModel = ann.clone().into();
    row.must_change_password = Set(true);
    row.update(&f.db).await.unwrap();

    let (status, body) = request_reset(&f, "  ANN@example.com ").await;
    assert_eq!(
        (status, body),
        (StatusCode::ACCEPTED, json!({ "accepted": true }))
    );
    let mails = f.deliver().await;
    let mail = only_to(&mails, ANN);
    assert_eq!(mail.from_name, "Contoso");
    assert!(mail.subject.contains("Reset your Contoso password"));
    let token = token_in(mail, "/login/reset");

    let (status, body) = complete(&f, &token, "short").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = complete(&f, &token, NEW_PASSWORD).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(password_is(&f, ann.id, NEW_PASSWORD).await);
    let after = users::Entity::find_by_id(ann.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.must_change_password);

    // Every refresh token of the user is dead.
    let (status, body) = f.refresh(&refresh, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    // Single use.
    let (status, body) = complete(&f, &token, "yet another passphrase").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_token"))
    );
    assert!(password_is(&f, ann.id, NEW_PASSWORD).await);

    let notices = f.deliver().await;
    assert!(
        only_to(&notices, ANN)
            .subject
            .contains("password was changed")
    );
    assert_eq!(
        common::mgmt::audited(&f.db, "user.password_reset_complete", ann.id)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn reset_never_reveals_whether_an_account_exists() {
    let f = Fixture::with_email().await;
    f.verify(&f.user).await;
    let unverified = common::seed::add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    let disabled = common::seed::add_user(&f.db, f.tenant.id, "cy@example.com", false).await;
    let disabled = f.verify(&disabled).await;
    let mut row: users::ActiveModel = disabled.into();
    row.disabled = Set(true);
    row.update(&f.db).await.unwrap();

    let mut answers = Vec::new();
    for email in [
        ANN,
        &unverified.email,
        "cy@example.com",
        "nobody@example.com",
    ] {
        answers.push(request_reset(&f, email).await);
    }
    for answer in &answers {
        assert_eq!(answer, &answers[0]);
    }
    assert_eq!(
        answers[0],
        (StatusCode::ACCEPTED, json!({ "accepted": true }))
    );
    // Only the enabled, verified account got a link.
    let mails = f.deliver().await;
    assert_eq!(mails.len(), 1, "{mails:#?}");
    assert_eq!(mails[0].to, ANN);

    // The per-address limit is the same for known and unknown addresses.
    for email in [ANN, "nobody@example.com"] {
        for _ in 0..2 {
            assert_eq!(request_reset(&f, email).await.0, StatusCode::ACCEPTED);
        }
        let (status, body) = request_reset(&f, email).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
        );
    }
}

#[tokio::test]
async fn reset_links_expire_and_stay_on_their_tenant() {
    let f = Fixture::with_email().await;
    let ann = f.verify(&f.user).await;
    directory::create_tenant(
        &f.db,
        &f.config,
        NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    request_reset(&f, ANN).await;
    let token = token_in(only_to(&f.deliver().await, ANN), "/login/reset");

    // Same token, other tenant's host (and Origin): unknown there.
    let body = json!({ "token": token, "new_password": NEW_PASSWORD });
    let (status, _, resp) = f
        .browser()
        .post_json(
            &at("fabrikam", "/api/authn/email/reset"),
            &body,
            "https://fabrikam.id.example.test",
        )
        .await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_token"))
    );
    // CSRF: the right host but a foreign Origin.
    let (status, _, _) = f
        .browser()
        .post_json(
            "/api/authn/email/reset",
            &body,
            "https://fabrikam.id.example.test",
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Expired.
    email_tokens::Entity::update_many()
        .col_expr(
            email_tokens::Column::ExpiresAt,
            Expr::value(chrono::Utc::now().fixed_offset() - chrono::Duration::seconds(1)),
        )
        .exec(&f.db)
        .await
        .unwrap();
    let (status, resp) = complete(&f, &token, NEW_PASSWORD).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_token"))
    );
    assert!(password_is(&f, ann.id, PASSWORD).await);

    // A newer request voids the older link.
    request_reset(&f, ANN).await;
    let first = token_in(only_to(&f.deliver().await, ANN), "/login/reset");
    request_reset(&f, ANN).await;
    let second = token_in(only_to(&f.deliver().await, ANN), "/login/reset");
    assert_eq!(
        complete(&f, &first, NEW_PASSWORD).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        complete(&f, &second, NEW_PASSWORD).await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn reset_is_unavailable_without_smtp() {
    let f = Fixture::new().await;
    let (status, body) = request_reset(&f, ANN).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    let mut browser = f.browser();
    let url = common::browser::authorize_url("web-app", common::flow::WEB_CB, "openid", &[]);
    let tx = browser.authorize(&url).await.unwrap();
    let (_, _, view) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(view["features"]["password_reset"], false);

    let f = Fixture::with_email().await;
    let mut browser = f.browser();
    let tx = browser.authorize(&url).await.unwrap();
    let (_, _, view) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(view["features"]["password_reset"], true);
}
