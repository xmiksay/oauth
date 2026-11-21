//! IdP presets against mock upstreams: Entra (multi-tenant `{tenantid}`
//! issuer, `tid`, allowed tenants, `xms_edov`), the per-IdP
//! `trust_upstream_email`, Google's hosted domain and the GitHub adapter.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::{Method, StatusCode};
use common::{
    federation::{Fed, IDPS, code_of, follow, login_error},
    github::FakeGithub,
    mgmt::audited_any,
};
use entity::{user_identities, users};
use oauth_server::directory;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Value, json};

const T1: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
const T2: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

async fn user_by_email(fed: &Fed, email: &str) -> Option<users::Model> {
    directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, email)
        .await
        .unwrap()
}

async fn subject_of(fed: &Fed, user_id: uuid::Uuid) -> String {
    user_identities::Entity::find()
        .filter(user_identities::Column::UserId.eq(user_id))
        .one(&fed.f.db)
        .await
        .unwrap()
        .unwrap()
        .subject
}

async fn last_reason(fed: &Fed) -> String {
    let events = audited_any(&fed.f.db, "sign_in").await;
    events.last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// An Entra-like upstream: discovery names the `{tenantid}` template, ID
/// tokens come from tenant `tid` (issuer filled in) without
/// `email_verified`.
fn entra_tokens(fed: &Fed, iss_tid: &str, tid: &str, edov: Value) {
    fed.up
        .set_discovery_issuer(&format!("{}/{{tenantid}}/v2.0", fed.up.issuer));
    fed.up.tweak(common::upstream::Tweak::Issuer(format!(
        "{}/{iss_tid}/v2.0",
        fed.up.issuer
    )));
    fed.up
        .set_extra_claims(json!({ "tid": tid, "xms_edov": edov, "email_verified": null }));
}

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

#[tokio::test]
async fn entra_multi_tenant_provisions_with_xms_edov() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({})).await;
    entra_tokens(&fed, T1, T1, json!(true));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    code_of(&location);
    let user = user_by_email(&fed, "pat@upstream.example").await.unwrap();
    assert!(user.email_verified);
    assert_eq!(subject_of(&fed, user.id).await, "upstream-sub-1");
}

#[tokio::test]
async fn entra_tenant_must_match_the_issuer_and_be_allowed() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({ "allowed_tenants": [T2.to_uppercase()] })).await;
    // A token from tenant T1 claiming to be T2.
    entra_tokens(&fed, T1, T2, json!(true));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "id_token_tid");
    entra_tokens(&fed, T1, T1, json!(true));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "tenant_not_allowed");
    entra_tokens(&fed, T2, T2, json!(true));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    code_of(&location);
}

#[tokio::test]
async fn unverified_entra_email_needs_the_trust_flag() {
    let fed = Fed::new().await;
    let idp = entra_idp(&fed, json!({})).await;
    entra_tokens(&fed, T1, T1, Value::Null);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_no_email"));
    let out = fed
        .patch_idp(&idp, json!({ "trust_upstream_email": true }))
        .await;
    assert_eq!(out["trust_upstream_email"], true);
    // Not a repoint: nothing about the provider's identity changed.
    assert_eq!(out["linked_users"], 0);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    code_of(&location);
    assert!(user_by_email(&fed, "pat@upstream.example").await.is_some());
}

#[tokio::test]
async fn google_hosted_domain_is_requested_and_enforced() {
    let fed = Fed::new().await;
    let idp = fed
        .idp(json!({ "kind": "google", "hosted_domain": "Contoso.com" }))
        .await;
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(fed.up.last_authorize()["hd"], "contoso.com");
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "id_token_hd");
    fed.up.set_extra_claims(json!({ "hd": "fabrikam.com" }));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(last_reason(&fed).await, "id_token_hd");
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    fed.up.set_extra_claims(json!({ "hd": "contoso.com" }));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    code_of(&location);
}

async fn github_sign_in(fed: &Fed, gh: &FakeGithub, idp: &str, extra: &[(&str, &str)]) -> String {
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, extra).await;
    let url = fed.begin(&mut browser, &tx, idp).await;
    follow(&mut browser, &gh.authorize(&url)).await
}

#[tokio::test]
async fn github_signs_in_by_numeric_id_with_the_verified_primary_email() {
    let fed = Fed::new().await;
    let gh = FakeGithub::start().await;
    let idp = fed
        .idp(json!({ "kind": "github", "issuer": gh.base }))
        .await;
    let location = github_sign_in(&fed, &gh, &idp, &[]).await;
    assert_eq!(fed.amr(&location).await, ["fed"]);
    assert!(gh.user_agent_seen());
    let user = user_by_email(&fed, "octo@github.example").await.unwrap();
    assert!(user.email_verified);
    assert_eq!(user.display_name, "The Octocat");
    assert_eq!(subject_of(&fed, user.id).await, "583231");
    // Same id, other profile: the same user.
    gh.set_account(json!({ "id": 583231, "login": "renamed" }), json!([]));
    let location = github_sign_in(&fed, &gh, &idp, &[]).await;
    code_of(&location);
    // An unverified primary is never used.
    gh.set_account(
        json!({ "id": 7, "login": "eve" }),
        json!([
            { "email": "eve@github.example", "primary": true, "verified": false },
            { "email": "eve2@github.example", "primary": false, "verified": true },
        ]),
    );
    let location = github_sign_in(&fed, &gh, &idp, &[]).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_no_email"));
}

#[tokio::test]
async fn github_email_errors_are_failures_but_a_missing_scope_is_no_email() {
    let fed = Fed::new().await;
    let gh = FakeGithub::start().await;
    let idp = fed
        .idp(json!({ "kind": "github", "issuer": gh.base }))
        .await;
    // An outage is not "no email": the sign-in fails and the audit says why.
    gh.set_emails_status(Some(StatusCode::INTERNAL_SERVER_ERROR));
    let location = github_sign_in(&fed, &gh, &idp, &[]).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "github_emails");
    // Without the `user:email` scope (403 / 404) there is just no email.
    for status in [StatusCode::FORBIDDEN, StatusCode::NOT_FOUND] {
        gh.set_emails_status(Some(status));
        let location = github_sign_in(&fed, &gh, &idp, &[]).await;
        assert_eq!(login_error(&location).as_deref(), Some("upstream_no_email"));
    }
    // A user linked earlier still signs in when the scope is missing.
    gh.set_emails_status(None);
    code_of(&github_sign_in(&fed, &gh, &idp, &[]).await);
    gh.set_emails_status(Some(StatusCode::FORBIDDEN));
    code_of(&github_sign_in(&fed, &gh, &idp, &[]).await);
}

#[tokio::test]
async fn github_refuses_demanded_reauthentication() {
    let fed = Fed::new().await;
    let gh = FakeGithub::start().await;
    let idp = fed
        .idp(json!({ "kind": "github", "issuer": gh.base }))
        .await;
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[("prompt", "login")]).await;
    let (status, body) = browser
        .step(&tx, &format!("federation/{idp}"), json!({}))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(last_reason(&fed).await, "reauth_unsupported");
}

#[tokio::test]
async fn presets_have_defaults_and_rules() {
    let fed = Fed::new().await;
    let post = |body: Value| fed.api(Method::POST, IDPS, Some(body));
    let base = |extra: Value| {
        let mut body = json!({ "name": "P", "client_id": "c" });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        body
    };
    let (status, gh) = post(base(json!({ "kind": "github" }))).await;
    assert_eq!(status, StatusCode::CREATED, "{gh}");
    assert_eq!(gh["issuer"], "https://github.com");
    assert_eq!(gh["scopes"], json!(["read:user", "user:email"]));
    assert_eq!(gh["kind"], "github");
    let id = gh["id"].as_str().unwrap();
    let path = format!("{IDPS}/{id}");
    let (status, out) = fed
        .api(
            Method::PATCH,
            &path,
            Some(json!({ "kind": "github", "name": "GH" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    for (body, needle) in [
        (json!({ "kind": "oidc" }), "kind"),
        (json!({ "trust_upstream_email": true }), "github"),
        (json!({ "hosted_domain": "contoso.com" }), "hosted_domain"),
    ] {
        let (status, out) = fed.api(Method::PATCH, &path, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
        assert!(out.to_string().contains(needle), "{out}");
    }
    let (status, google) = post(base(json!({ "name": "G", "kind": "google" }))).await;
    assert_eq!(status, StatusCode::CREATED, "{google}");
    assert_eq!(google["issuer"], "https://accounts.google.com");
    assert_eq!(google["hosted_domain"], Value::Null);
    assert_eq!(google["allowed_tenants"], json!([]));
    assert_eq!(google["trust_upstream_email"], false);
    let multi = "https://login.microsoftonline.com/{tenantid}/v2.0";
    for (body, needle) in [
        (json!({ "kind": "entra" }), "issuer"),
        (json!({ "kind": "entra", "issuer": multi }), "discovery_url"),
        (
            json!({ "issuer": multi, "discovery_url": "https://x.example/d" }),
            "entra",
        ),
        (
            json!({ "kind": "saml", "issuer": "https://x.example" }),
            "kind",
        ),
        (
            json!({ "issuer": "https://x.example", "scopes": ["email"] }),
            "openid",
        ),
        (
            json!({ "kind": "entra", "issuer": "https://x.example/t", "allowed_tenants": [T1] }),
            "allowed_tenants",
        ),
    ] {
        let (status, out) = post(base(body.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} {out}");
        assert!(out.to_string().contains(needle), "{out}");
    }
    let (status, entra) = post(base(json!({
        "name": "E", "kind": "entra", "issuer": multi,
        "discovery_url": "https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration",
        "allowed_tenants": [T1],
    })))
    .await;
    assert_eq!(status, StatusCode::CREATED, "{entra}");
    assert_eq!(entra["issuer"], multi);
    assert_eq!(entra["allowed_tenants"], json!([T1]));
    let created = audited_any(&fed.f.db, "identity_provider.create").await;
    assert_eq!(created.last().unwrap()["kind"], "entra");
}
