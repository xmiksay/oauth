// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Email links: binding, single purpose, superseding, timing independence.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    ORIGIN,
    flow::{Fixture, PASSWORD},
    mail::{only_to, token_in},
    mgmt::{call, mint_user_token, user_with_roles},
};
use entity::{audit_events, email_tokens, enums::DirectoryRole, enums::EmailTokenPurpose, users};
use oauth_server::mail::links;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter, TransactionTrait,
};
use serde_json::{Value, json};
use uuid::Uuid;

const ANN: &str = "ann@example.com";

async fn admin(f: &Fixture) -> String {
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::UserAdmin],
    )
    .await;
    mint_user_token(&f.db, &f.config, &f.tenant, &admin).await
}

async fn redeem(f: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let (status, _, body) = f.browser().post_json(path, &body, ORIGIN).await;
    (status, body)
}

async fn set_pw(f: &Fixture, path: &str, token: &str) -> StatusCode {
    let body = json!({ "token": token, "new_password": "some new passphrase" });
    redeem(f, path, body).await.0
}

async fn request_reset(f: &Fixture, email: &str) -> StatusCode {
    let body = json!({ "email": email });
    let (status, _) = redeem(f, "/api/authn/password-reset", body).await;
    status
}

async fn live_tokens(f: &Fixture, user: Uuid) -> u64 {
    email_tokens::Entity::find()
        .filter(email_tokens::Column::UserId.eq(user))
        .filter(email_tokens::Column::ConsumedAt.is_null())
        .count(&f.db)
        .await
        .unwrap()
}

/// An invited user (no password) with a pending invite and reset link.
async fn invitee(f: &Fixture, token: &str) -> (Uuid, String, String) {
    let body = json!({ "email": "inv@example.com", "display_name": "Inv", "invite": true });
    let (_, created) = call(
        &f.app,
        Method::POST,
        "/api/v1/users",
        Some(token),
        Some(&body),
    )
    .await;
    let id: Uuid = created["user"]["id"].as_str().unwrap().parse().unwrap();
    let invite = token_in(
        only_to(&f.deliver().await, "inv@example.com"),
        "/login/invite",
    );
    assert_eq!(
        request_reset(f, "inv@example.com").await,
        StatusCode::ACCEPTED
    );
    let reset = token_in(
        only_to(&f.deliver().await, "inv@example.com"),
        "/login/reset",
    );
    (id, invite, reset)
}

#[tokio::test]
async fn reset_answers_before_any_account_dependent_work() {
    let f = Fixture::with_email().await;
    f.verify(&f.user).await;
    // While email_tokens is locked, any account-dependent step of the
    // request would block; the answer must not wait for it.
    let lock = f.db.begin().await.unwrap();
    lock.execute_unprepared("LOCK TABLE email_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    for email in [ANN, "nobody@example.com"] {
        let answer =
            tokio::time::timeout(std::time::Duration::from_secs(5), request_reset(&f, email));
        assert_eq!(
            answer.await.expect("answered while locked"),
            StatusCode::ACCEPTED
        );
    }
    assert_eq!(f.outbox_rows().await, 0, "nothing queued yet");
    lock.commit().await.unwrap();
    f.settle().await;
    assert_eq!(f.outbox_rows().await, 1);
    // Anonymous actor: the requester isn't known to be the user.
    let event = audit_events::Entity::find()
        .filter(audit_events::Column::EventType.eq("user.password_reset_request"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((event.actor_id, event.target_id), (None, Some(f.user.id)));
}

#[tokio::test]
async fn patch_me_keeps_the_me_shape() {
    let f = Fixture::with_email().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let body = json!({ "display_name": "Ann Renamed" });
    let (status, me) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/me",
        Some(&token),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["features"], json!({ "email": true }));
    let (_, me) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/me",
        Some(&token),
        Some(&body),
    )
    .await;
    assert_eq!(me["features"], json!({ "email": true }), "unchanged PATCH");
}

#[tokio::test]
async fn tokens_only_work_for_the_address_they_were_sent_to() {
    let f = Fixture::with_email().await;
    let token = admin(&f).await;
    let stale = f.verify(&f.user).await;
    let path = format!("/api/v1/users/{}", f.user.id);
    let body = json!({ "email": "ann2@example.com" });
    let (status, _) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::OK);
    // A reset issued from a stale read of the user (as a racing request
    // would) names the old address and never works.
    links::send(
        &f.db,
        &f.config,
        &f.tenant,
        &stale,
        EmailTokenPurpose::Reset,
        None,
    )
    .await
    .unwrap();
    let mails = f.deliver().await;
    let reset = mails
        .iter()
        .find(|m| m.subject.starts_with("Reset"))
        .unwrap();
    assert_eq!(reset.to, ANN);
    let link = token_in(reset, "/login/reset");
    assert_eq!(
        set_pw(&f, "/api/authn/email/reset", &link).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn links_serve_only_their_purpose_and_enabled_users() {
    let f = Fixture::with_email().await;
    let token = admin(&f).await;
    let (id, invite, reset) = invitee(&f, &token).await;
    for t in [&invite, &reset] {
        let (status, _) = redeem(&f, "/api/authn/email/verify", json!({ "token": t })).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "verify must not take reset/invite links"
        );
    }
    // Disabled users can't redeem anything.
    let mut row: users::ActiveModel = users::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .into();
    row.disabled = Set(true);
    let user = row.update(&f.db).await.unwrap();
    assert_eq!(
        set_pw(&f, "/api/authn/email/invite", &invite).await,
        StatusCode::BAD_REQUEST
    );
    let mut row: users::ActiveModel = user.into();
    row.disabled = Set(false);
    row.update(&f.db).await.unwrap();
    // Accepting the invitation voids the reset link sent meanwhile.
    assert_eq!(
        set_pw(&f, "/api/authn/email/invite", &invite).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        set_pw(&f, "/api/authn/email/reset", &reset).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn a_password_supersedes_pending_links() {
    let f = Fixture::with_email().await;
    let token = admin(&f).await;
    // An invitation is refused once the user has a password, however set.
    let (id, invite, _reset) = invitee(&f, &token).await;
    let mut row: users::ActiveModel = users::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .into();
    row.password_hash = Set(Some(
        oauth_server::directory::password::hash(PASSWORD)
            .await
            .unwrap(),
    ));
    row.update(&f.db).await.unwrap();
    assert_eq!(
        set_pw(&f, "/api/authn/email/invite", &invite).await,
        StatusCode::BAD_REQUEST
    );

    // An admin reset and a self-service change void pending reset links.
    let ann = f.verify(&f.user).await;
    request_reset(&f, ANN).await;
    let link = token_in(only_to(&f.deliver().await, ANN), "/login/reset");
    let path = format!("/api/v1/users/{}/reset-password", ann.id);
    let (status, _) = call(&f.app, Method::POST, &path, Some(&token), Some(&json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        set_pw(&f, "/api/authn/email/reset", &link).await,
        StatusCode::BAD_REQUEST
    );

    let bob = common::seed::add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    f.verify(&bob).await;
    request_reset(&f, "bob@example.com").await;
    let link = token_in(
        only_to(&f.deliver().await, "bob@example.com"),
        "/login/reset",
    );
    let bob_token = mint_user_token(&f.db, &f.config, &f.tenant, &bob).await;
    let body = json!({ "current_password": PASSWORD, "new_password": "bob's new passphrase" });
    let (status, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/me/change-password",
        Some(&bob_token),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        set_pw(&f, "/api/authn/email/reset", &link).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn address_changes_void_every_link_and_reinvite() {
    let f = Fixture::with_email().await;
    let token = admin(&f).await;
    let (id, _invite, _reset) = invitee(&f, &token).await;
    let path = format!("/api/v1/users/{id}");
    let body = json!({ "email": "inv2@example.com" });
    let (status, _) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::OK);
    // Only the fresh invitation (to the new address) is left; the old
    // address, never verified, gets no notice.
    assert_eq!(live_tokens(&f, id).await, 1);
    let mails = f.deliver().await;
    assert_eq!(mails.len(), 1, "{mails:#?}");
    let link = token_in(only_to(&mails, "inv2@example.com"), "/login/invite");
    assert_eq!(
        set_pw(&f, "/api/authn/email/invite", &link).await,
        StatusCode::NO_CONTENT
    );

    // Self-service change: the applied change leaves no live link behind.
    let ann = f.verify(&f.user).await;
    request_reset(&f, ANN).await;
    f.deliver().await;
    let ann_token = mint_user_token(&f.db, &f.config, &f.tenant, &ann).await;
    let body = json!({ "new_email": "ann2@example.com", "password": PASSWORD });
    call(
        &f.app,
        Method::POST,
        "/api/v1/me/email",
        Some(&ann_token),
        Some(&body),
    )
    .await;
    let link = token_in(
        only_to(&f.deliver().await, "ann2@example.com"),
        "/myaccount/verify-email",
    );
    let (status, _) = redeem(&f, "/api/authn/email/verify", json!({ "token": link })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(live_tokens(&f, ann.id).await, 0);
}

#[tokio::test]
async fn saturated_detached_work_is_dropped_with_the_same_answer() {
    let f = Fixture::with_email().await;
    f.verify(&f.user).await;
    let held = f
        .detached
        .clone()
        .try_acquire_many_owned(u32::try_from(oauth_server::app::MAX_DETACHED).unwrap())
        .unwrap();
    let reset = json!({ "email": ANN });
    let dropped = redeem(&f, "/api/authn/password-reset", reset.clone()).await;
    f.settle().await;
    assert_eq!(f.outbox_rows().await, 0, "dropped, not queued");
    drop(held);
    let queued = redeem(&f, "/api/authn/password-reset", reset).await;
    f.settle().await;
    assert_eq!(f.outbox_rows().await, 1);
    // Same status and body whether the work ran or was dropped.
    assert_eq!(dropped, queued);
    assert_eq!(queued, (StatusCode::ACCEPTED, json!({ "accepted": true })));
}

#[tokio::test]
async fn swept_devices_do_not_silence_the_sign_in_notice() {
    let f = Fixture::with_email().await;
    f.verify(&f.user).await;
    let url = common::browser::authorize_url("web-app", common::flow::WEB_CB, "openid", &[]);
    f.browser().login_for_code(&url, ANN).await;
    assert!(f.deliver().await.is_empty(), "first sign-in ever");
    // A year idle: the sweeper removed every device record.
    f.db.execute_unprepared("DELETE FROM known_devices")
        .await
        .unwrap();
    f.browser().login_for_code(&url, ANN).await;
    let mails = f.deliver().await;
    assert!(only_to(&mails, ANN).subject.contains("New sign-in"));
}
