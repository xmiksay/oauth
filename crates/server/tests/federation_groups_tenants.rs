//! Federation group mappings on a multi-tenant (`{tenantid}`) Entra
//! provider: only with `allowed_tenants`, since any Entra tenant can put
//! well-known `wids` / its own `roles` in a token.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::{Method, StatusCode};
use common::{
    federation::{Fed, IDPS, login_error},
    groups::{group, map, mapped, memberships, sign_in_with, uuid},
    mgmt::{audited_any, call},
    upstream::Account,
};
use entity::{group_members, idp_group_mappings};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde_json::{Value, json};
use uuid::Uuid;

const T1: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
const T2: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
/// Global Administrator's role template id: the same in every tenant.
const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";

async fn entra_idp(fed: &Fed, extra: Value) -> String {
    let mut body = json!({
        "kind": "entra",
        "issuer": format!("{}/{{tenantid}}/v2.0", fed.up.issuer),
        "discovery_url": format!("{}/.well-known/openid-configuration", fed.up.issuer),
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    fed.idp(body).await
}

/// ID tokens from Entra tenant `tid`, issuer filled in.
fn from_tenant(fed: &Fed, tid: &str) {
    fed.up
        .set_discovery_issuer(&format!("{}/{{tenantid}}/v2.0", fed.up.issuer));
    fed.up.tweak(common::upstream::Tweak::Issuer(format!(
        "{}/{tid}/v2.0",
        fed.up.issuer
    )));
    fed.up
        .set_extra_claims(json!({ "tid": tid, "xms_edov": true }));
}

async fn patch(fed: &Fed, idp: &str, body: Value) -> (StatusCode, Value) {
    fed.api(Method::PATCH, &format!("{IDPS}/{idp}"), Some(body))
        .await
}

#[tokio::test]
async fn mappings_need_allowed_tenants_on_a_multi_tenant_entra() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({})).await;
    let admins = group(&fed, "k8s-admins").await;
    let (status, out) = map(&fed, &idp, "wids", GLOBAL_ADMIN, admins).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    assert!(out.to_string().contains("allowed_tenants"), "{out}");

    fed.patch_idp(&idp, json!({ "allowed_tenants": [T1] }))
        .await;
    mapped(&fed, &idp, "wids", GLOBAL_ADMIN, admins).await;
    // Clearing the pin while mappings exist is refused, and changes nothing.
    let (status, out) = patch(&fed, &idp, json!({ "allowed_tenants": [] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    assert!(out.to_string().contains("allowed_tenants"), "{out}");
    let (_, got) = fed.api(Method::GET, &format!("{IDPS}/{idp}"), None).await;
    assert_eq!(got["allowed_tenants"], json!([T1]));
    // Another pinned tenant list is fine.
    fed.patch_idp(&idp, json!({ "allowed_tenants": [T1, T2] }))
        .await;

    // A templated issuer on a single-tenant provider with mappings: the
    // same 400 (the switch would open it to every tenant).
    let issuer = format!("{}/{T1}/v2.0", fed.up.issuer);
    let single = entra_idp(&fed, json!({ "name": "Single", "issuer": issuer })).await;
    mapped(&fed, &single, "wids", GLOBAL_ADMIN, admins).await;
    let templated = format!("{}/{{tenantid}}/v2.0", fed.up.issuer);
    let (status, out) = patch(&fed, &single, json!({ "issuer": templated })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    let both = json!({ "issuer": templated, "allowed_tenants": [T1] });
    fed.patch_idp(&single, both).await;
}

#[tokio::test]
async fn only_allowed_tenants_get_mapped_memberships() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({ "allowed_tenants": [T1] })).await;
    let admins = group(&fed, "k8s-admins").await;
    mapped(&fed, &idp, "wids", GLOBAL_ADMIN, admins).await;
    let claims = json!({ "wids": [GLOBAL_ADMIN] });
    from_tenant(&fed, T2);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    from_tenant(&fed, T1);
    let user = sign_in_with(&fed, &idp, claims).await;
    assert_eq!(
        memberships(&fed, user.id).await,
        vec![(admins, false, true)]
    );
}

/// A mapping stored before the rule, on a provider that accepts every
/// tenant, decides nothing: no membership is added, none is removed.
#[tokio::test]
async fn legacy_mappings_on_an_open_provider_decide_nothing() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({})).await;
    let admins = group(&fed, "k8s-admins").await;
    idp_group_mappings::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(fed.f.tenant.id),
        idp_id: Set(uuid(&json!(idp))),
        claim: Set("wids".into()),
        value: Set(GLOBAL_ADMIN.into()),
        group_id: Set(admins),
        created_at: Set(chrono::Utc::now().fixed_offset()),
    }
    .insert(&fed.f.db)
    .await
    .unwrap();
    from_tenant(&fed, T2);
    let user = sign_in_with(&fed, &idp, json!({ "wids": [GLOBAL_ADMIN] })).await;
    assert!(memberships(&fed, user.id).await.is_empty());

    // A membership the mapping kept (before the rule) is not removed when
    // the claim value is gone either.
    group_members::ActiveModel {
        tenant_id: Set(fed.f.tenant.id),
        group_id: Set(admins),
        user_id: Set(user.id),
        created_at: Set(chrono::Utc::now().fixed_offset()),
        manual: Set(false),
        idp_id: Set(Some(uuid(&json!(idp)))),
    }
    .insert(&fed.f.db)
    .await
    .unwrap();
    let again = sign_in_with(&fed, &idp, json!({})).await;
    assert_eq!(again.id, user.id);
    assert_eq!(
        memberships(&fed, user.id).await,
        vec![(admins, false, true)]
    );
}

/// Removing a tenant from `allowed_tenants` while its user is mid-sign-in:
/// the callback, verified against the wider list, fails instead of getting
/// mapped groups.
#[tokio::test]
async fn narrowing_allowed_tenants_during_the_exchange_wins() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({ "allowed_tenants": [T1, T2] })).await;
    let admins = group(&fed, "k8s-admins").await;
    mapped(&fed, &idp, "wids", GLOBAL_ADMIN, admins).await;
    let (app, token, path) = (
        fed.f.app.clone(),
        fed.admin.clone(),
        format!("{IDPS}/{idp}"),
    );
    fed.up.on_token(Box::new(move || {
        Box::pin(async move {
            let body = json!({ "allowed_tenants": [T2] });
            let (status, out) = call(&app, Method::PATCH, &path, Some(&token), Some(&body)).await;
            assert_eq!(status, StatusCode::OK, "{out}");
        })
    }));
    from_tenant(&fed, T1);
    let mut account = Account::new("upstream-sub-1", "pat@upstream.example");
    account.extra = json!({ "wids": [GLOBAL_ADMIN] });
    fed.up.set_account(account);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    let events = audited_any(&fed.f.db, "sign_in").await;
    assert_eq!(events.last().unwrap()["reason"], "idp_repointed");
}

/// De-listing a tenant drops the memberships its users got through the
/// mappings: they can't sign in again to have them re-synced.
#[tokio::test]
async fn narrowing_allowed_tenants_drops_mapped_memberships() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({ "allowed_tenants": [T1, T2] })).await;
    let admins = group(&fed, "k8s-admins").await;
    mapped(&fed, &idp, "wids", GLOBAL_ADMIN, admins).await;
    from_tenant(&fed, T2);
    let user = sign_in_with(&fed, &idp, json!({ "wids": [GLOBAL_ADMIN] })).await;
    assert_eq!(
        memberships(&fed, user.id).await,
        vec![(admins, false, true)]
    );

    fed.patch_idp(&idp, json!({ "allowed_tenants": [T1] }))
        .await;
    assert!(memberships(&fed, user.id).await.is_empty());
    let events = audited_any(&fed.f.db, "identity_provider.update").await;
    let last = events.last().unwrap();
    assert_eq!(last["memberships_removed"], 1);
    assert_eq!(last["identities_removed"], 0);
    // The identity stays linked; only the de-listed tenant is refused.
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
}
