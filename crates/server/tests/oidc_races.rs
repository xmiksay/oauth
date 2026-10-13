// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Concurrent redemption of one code / refresh token, and the code and
//! refresh invariants around them.
mod common;

use axum::http::StatusCode;
use common::{
    browser::authorize_url,
    flow::{Fixture, VERIFIER, WEB_CB},
};
use entity::{authorization_codes, opaque_access_tokens, refresh_tokens};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::json;

/// Refresh tokens of the family that are neither rotated nor revoked.
async fn live_in_family(f: &Fixture, family: uuid::Uuid) -> u64 {
    refresh_tokens::Entity::find()
        .filter(refresh_tokens::Column::FamilyId.eq(family))
        .filter(refresh_tokens::Column::RotatedAt.is_null())
        .filter(refresh_tokens::Column::RevokedAt.is_null())
        .count(&f.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn concurrent_refresh_leaves_no_live_token_in_the_family() {
    let f = Fixture::new().await;
    for round in 0..5 {
        let (_, tokens) = f
            .web_tokens(
                "openid offline_access api://orders/Orders.Read",
                "ann@example.com",
            )
            .await;
        let rt = tokens["refresh_token"].as_str().unwrap();
        let family = refresh_tokens::Entity::find()
            .filter(refresh_tokens::Column::TokenHash.eq(oauth_server::secret::hash(rt)))
            .one(&f.db)
            .await
            .unwrap()
            .unwrap()
            .family_id;
        let (a, b) = tokio::join!(f.refresh(rt, None), f.refresh(rt, None));
        let ok = [a.0, b.0].iter().filter(|s| **s == StatusCode::OK).count();
        assert_eq!(ok, 1, "round {round}: {a:?} / {b:?}");
        assert_eq!(
            live_in_family(&f, family).await,
            0,
            "round {round}: a token survived reuse"
        );
    }
}

#[tokio::test]
async fn concurrent_code_redemption_leaves_no_live_token() {
    let f = Fixture::new().await;
    for round in 0..5 {
        let mut browser = f.browser();
        let url = authorize_url(
            "web-app",
            WEB_CB,
            "offline_access api://ledger/Ledger.Read",
            &[],
        );
        let code = browser.login_for_code(&url, "ann@example.com").await;
        let (a, b) = tokio::join!(
            f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB),
            f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB),
        );
        let ok = [a.0, b.0].iter().filter(|s| **s == StatusCode::OK).count();
        // Exactly one consume wins; the other sees the code used.
        assert_eq!(ok, 1, "round {round}: {a:?} / {b:?}");
        let code_row = authorization_codes::Entity::find()
            .filter(authorization_codes::Column::CodeHash.eq(oauth_server::secret::hash(&code)))
            .one(&f.db)
            .await
            .unwrap()
            .unwrap();
        let live_refresh = refresh_tokens::Entity::find()
            .filter(refresh_tokens::Column::AuthorizationCodeId.eq(code_row.id))
            .filter(refresh_tokens::Column::RevokedAt.is_null())
            .count(&f.db)
            .await
            .unwrap();
        let live_opaque = opaque_access_tokens::Entity::find()
            .filter(opaque_access_tokens::Column::AuthorizationCodeId.eq(code_row.id))
            .filter(opaque_access_tokens::Column::RevokedAt.is_null())
            .count(&f.db)
            .await
            .unwrap();
        assert_eq!(
            (live_refresh, live_opaque),
            (0, 0),
            "round {round}: replay left tokens alive"
        );
    }
}

#[tokio::test]
async fn wrong_verifier_does_not_burn_the_code() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let code = browser
        .login_for_code(
            &authorize_url("web-app", WEB_CB, "openid", &[]),
            "ann@example.com",
        )
        .await;
    let other = format!("{}x", &VERIFIER[..VERIFIER.len() - 1]);
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", WEB_CB),
        ("code_verifier", other.as_str()),
    ];
    let basic = Some(("web-app", f.web_secret.as_str()));
    let (status, _, body) = f.post_form("/contoso/oauth2/token", &form, basic).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let (status, body) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn refresh_narrowed_to_oidc_keeps_the_resource() {
    let f = Fixture::new().await;
    let (_, tokens) = f
        .web_tokens(
            "openid offline_access api://orders/Orders.Read",
            "ann@example.com",
        )
        .await;
    let (status, narrowed) = f
        .refresh(tokens["refresh_token"].as_str().unwrap(), Some("openid"))
        .await;
    assert_eq!(status, StatusCode::OK, "{narrowed}");
    assert_eq!(narrowed["scope"], "openid");
    let (status, full) = f
        .refresh(narrowed["refresh_token"].as_str().unwrap(), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{full}");
    assert_eq!(
        full["scope"],
        "api://orders/Orders.Read openid offline_access"
    );
    let at = f
        .verify_jwt(full["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["scp"], "Orders.Read");
    assert_eq!(at["roles"], json!(["Orders.Approver"]));
}

#[tokio::test]
async fn revocation_during_a_rotation_leaves_no_live_token() {
    use oauth_server::tokens::refresh::{self, NewRefresh};
    use sea_orm::TransactionTrait;

    let f = Fixture::new().await;
    let (_, tokens) = f
        .web_tokens("openid offline_access", "ann@example.com")
        .await;
    let stale = tokens["refresh_token"].as_str().unwrap().to_owned();
    let (_, rotated) = f.refresh(&stale, None).await;
    let live = rotated["refresh_token"].as_str().unwrap();
    let a = refresh::find(&f.db, f.tenant.id, live)
        .await
        .unwrap()
        .unwrap();

    // Another request mid-rotation: A rotated and B inserted, uncommitted.
    let txn = f.db.begin().await.unwrap();
    assert!(refresh::mark_rotated(&txn, a.id).await.unwrap());
    let b = refresh::issue(
        &txn,
        NewRefresh {
            tenant_id: a.tenant_id,
            family_id: a.family_id,
            client_app_id: a.application_id,
            user_id: a.user_id,
            session_id: a.session_id,
            authorization_code_id: a.authorization_code_id,
            scopes: &a.scopes,
            resource_app_id: a.resource_application_id,
            amr: &a.amr,
            auth_time: a.auth_time,
            expires_at: a.expires_at,
        },
    )
    .await
    .unwrap();

    // Meanwhile the stale token is replayed; its family revocation must
    // also catch B once the rotation commits.
    let (replayed, ()) = tokio::join!(f.refresh(&stale, None), async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        txn.commit().await.unwrap();
    });
    assert_eq!(replayed.0, StatusCode::BAD_REQUEST);
    assert_eq!(live_in_family(&f, a.family_id).await, 0);
    let (status, _) = f.refresh(&b, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let basic = Some(("web-app", f.web_secret.as_str()));
    let (_, _, body) = f
        .post_form("/contoso/oauth2/introspect", &[("token", &b)], basic)
        .await;
    assert_eq!(body, json!({ "active": false }));
}

#[tokio::test]
async fn a_revoked_row_kills_the_whole_family() {
    use sea_orm::ConnectionTrait;

    let f = Fixture::new().await;
    let (_, tokens) = f
        .web_tokens("openid offline_access", "ann@example.com")
        .await;
    let older = tokens["refresh_token"].as_str().unwrap().to_owned();
    let (_, rotated) = f.refresh(&older, None).await;
    let current = rotated["refresh_token"].as_str().unwrap().to_owned();
    // Only the older row is revoked (as a single-pass revocation racing a
    // rotation would leave it); the current token itself is untouched.
    let hash = oauth_server::secret::hash(&older);
    f.db.execute(
        sea_orm::sea_query::Query::update()
            .table(refresh_tokens::Entity)
            .value(
                refresh_tokens::Column::RevokedAt,
                chrono::Utc::now().fixed_offset(),
            )
            .and_where(refresh_tokens::Column::TokenHash.eq(hash)),
    )
    .await
    .unwrap();

    let basic = Some(("web-app", f.web_secret.as_str()));
    let (_, _, body) = f
        .post_form("/contoso/oauth2/introspect", &[("token", &current)], basic)
        .await;
    assert_eq!(body, json!({ "active": false }), "family has a revoked row");
    let (status, body) = f.refresh(&current, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let row = refresh_tokens::Entity::find()
        .filter(refresh_tokens::Column::TokenHash.eq(oauth_server::secret::hash(&current)))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.revoked_at.is_some(),
        "the refusal revoked the rest of the family"
    );
}
