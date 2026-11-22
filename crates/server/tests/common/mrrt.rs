//! Helpers for the multi-resource refresh tests (`oidc_mrrt*.rs`).

use axum::http::StatusCode;
use entity::{applications, enums::AppMfaPolicy, opaque_access_tokens};
use oauth_server::consent;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;

use super::flow::Fixture;

pub const LEDGER: &str = "api://ledger/Ledger.Read";

pub fn error(reply: &(StatusCode, Value)) -> (StatusCode, Option<&str>) {
    (reply.0, reply.1["error"].as_str())
}

/// Redeems `rt` for `scope`, expecting success; returns the rotated token.
pub async fn redeem_ok(f: &Fixture, rt: &str, scope: &str) -> (String, Value) {
    let (status, body) = f.refresh(rt, Some(scope)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (body["refresh_token"].as_str().unwrap().to_owned(), body)
}

/// Asserts the redemption of `rt` for `scope` is refused with `code`.
pub async fn refused(f: &Fixture, rt: &str, scope: &str, code: &str) {
    let reply = f.refresh(rt, Some(scope)).await;
    assert_eq!(
        error(&reply),
        (StatusCode::BAD_REQUEST, Some(code)),
        "{scope}"
    );
}

/// The user's own consent: web-app → ledger `Ledger.Read`.
pub async fn consent_to_ledger(f: &Fixture) {
    let values = ["Ledger.Read".to_owned()];
    consent::store_grant(
        &f.db,
        f.tenant.id,
        f.web.id,
        f.ledger.id,
        Some(f.user.id),
        &values,
    )
    .await
    .unwrap();
}

pub async fn set_mfa(f: &Fixture, app: &applications::Model, policy: AppMfaPolicy) {
    let mut row: applications::ActiveModel = app.clone().into();
    row.mfa_policy = Set(policy);
    row.update(&f.db).await.unwrap();
}

/// Unrevoked opaque access tokens for the ledger.
pub async fn live_ledger_tokens(f: &Fixture) -> usize {
    opaque_access_tokens::Entity::find()
        .filter(opaque_access_tokens::Column::ResourceApplicationId.eq(f.ledger.id))
        .filter(opaque_access_tokens::Column::RevokedAt.is_null())
        .all(&f.db)
        .await
        .unwrap()
        .len()
}

/// A `web-app` refresh token granted for `api://orders/Orders.Read`.
pub async fn orders_refresh_token(f: &Fixture) -> String {
    let (_, tokens) = f
        .web_tokens(
            "openid offline_access api://orders/Orders.Read",
            "ann@example.com",
        )
        .await;
    tokens["refresh_token"].as_str().unwrap().to_owned()
}
