//! Federation group mapping helpers: groups and mappings through the
//! management API, federated sign-ins carrying extra claims, membership rows.

use axum::http::{Method, StatusCode};
use entity::{group_members, users};
use oauth_server::directory;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    federation::{Fed, IDPS},
    upstream::Account,
};

pub const EMAIL: &str = "pat@upstream.example";

pub fn uuid(v: &Value) -> Uuid {
    Uuid::parse_str(v.as_str().unwrap()).unwrap()
}

pub async fn group(fed: &Fed, name: &str) -> Uuid {
    let body = json!({ "display_name": name });
    let (status, out) = fed.api(Method::POST, "/api/v1/groups", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{out}");
    uuid(&out["id"])
}

pub async fn map(
    fed: &Fed,
    idp: &str,
    claim: &str,
    value: &str,
    group: Uuid,
) -> (StatusCode, Value) {
    let body = json!({ "claim": claim, "value": value, "group_id": group });
    let path = format!("{IDPS}/{idp}/group-mappings");
    fed.api(Method::POST, &path, Some(body)).await
}

pub async fn mapped(fed: &Fed, idp: &str, claim: &str, value: &str, group: Uuid) -> String {
    let (status, out) = map(fed, idp, claim, value, group).await;
    assert_eq!(status, StatusCode::CREATED, "{out}");
    out["id"].as_str().unwrap().to_owned()
}

/// Signs `extra` claims in as the default upstream account.
pub async fn sign_in_with(fed: &Fed, idp: &str, extra: Value) -> users::Model {
    let mut account = Account::new("upstream-sub-1", EMAIL);
    account.extra = extra;
    fed.up.set_account(account);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), idp).await;
    fed.amr(&location).await;
    directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, EMAIL)
        .await
        .unwrap()
        .unwrap()
}

/// The user's memberships: `(group, manual, kept by an IdP)`, by group.
pub async fn memberships(fed: &Fed, user: Uuid) -> Vec<(Uuid, bool, bool)> {
    let mut rows: Vec<_> = group_members::Entity::find()
        .filter(group_members::Column::UserId.eq(user))
        .all(&fed.f.db)
        .await
        .unwrap()
        .into_iter()
        .map(|m| (m.group_id, m.manual, m.idp_id.is_some()))
        .collect();
    rows.sort();
    rows
}

pub fn sorted(mut rows: Vec<(Uuid, bool, bool)>) -> Vec<(Uuid, bool, bool)> {
    rows.sort();
    rows
}

pub async fn add_manually(fed: &Fed, group: Uuid, user: Uuid) -> StatusCode {
    let path = format!("/api/v1/groups/{group}/members");
    let body = json!({ "user_id": user });
    fed.api(Method::POST, &path, Some(body)).await.0
}
