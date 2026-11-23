// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Client secret options (#46): caller-supplied values and non-expiring
//! secrets behind the tenant policy (the expiry warning job:
//! `secret_expiry_warnings.rs`).
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_admin_token, audited, call, mint_user_token, post, user_with_roles},
};
use entity::{client_secrets, enums::DirectoryRole, tenants};
use oauth_server::{bootstrap, directory};
use sea_orm::{ConnectionTrait, EntityTrait, TransactionTrait};
use serde_json::{Value, json};
use uuid::Uuid;

const APPS: &str = "/api/v1/applications";
const SUPPLIED: &str = "mZOWZylKwwVXXPmCV9rrSl3slrjp2bjUIQyc79qbsFo";
/// `openssl rand -hex 32`
const SUPPLIED_HEX: &str = "e83239adaf4444a9ae61ba14223b320a31e6ade2f006e2170651faff226e8718";

async fn new_app(f: &Fixture, token: &str, client_id: &str) -> String {
    let (st, app) = post(
        f,
        token,
        APPS,
        json!({ "client_id": client_id, "display_name": "Deployer" }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{app}");
    format!("{APPS}/{}/secrets", app["id"].as_str().unwrap())
}

async fn client_credentials(f: &Fixture, client_id: &str, secret: &str) -> StatusCode {
    let creds = [
        ("grant_type", "client_credentials"),
        ("scope", "api://ledger/.default"),
    ];
    f.post_form("/oauth2/token", &creds, Some((client_id, secret)))
        .await
        .0
}

#[tokio::test]
async fn a_caller_supplied_secret_is_checked_stored_hashed_and_never_echoed() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = new_app(&f, &token, "deployer").await;

    let hex32 = "9f86d081884c7d659a2feaa0c55ad015";
    let password = "password".repeat(8);
    // #81 review: repeated words off base64's 4-character grid.
    let password1 = format!("{}pas", "password1".repeat(5));
    let password17 = "passwordpassword1".repeat(4);
    let company = "MyCompanySecretKey2026".repeat(2);
    // #81 review: a repeated word plus a short tail has no whole-value period.
    let password_tail = format!("{}AbCd", "password".repeat(5));
    let company_tail = format!("{company}Xq9z");
    for weak in [
        "short",
        hex32,
        &"a".repeat(64),
        &format!("{SUPPLIED} x"),
        // #81: these passed the character-histogram estimate.
        &password,
        "abcdefghijklmnopqrstuvwxyz012345",
        "CompanyNameProductionSecret2026!",
        &password1,
        &password17,
        &company,
        &password_tail,
        &company_tail,
        // #81 review: sequential bytes, hex and base64 (bytes 0..31).
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    ] {
        let (st, body) = post(&f, &token, &path, json!({ "secret": weak })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(!body.to_string().contains(weak));
    }

    let (st, created) = post(&f, &token, &path, json!({ "secret": SUPPLIED })).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert!(created.get("secret").is_none(), "{created}");
    assert!(!created.to_string().contains(SUPPLIED));
    let hash = oauth_server::secret::hash(SUPPLIED);
    assert_eq!(
        created["hint"],
        format!("{:02x}{:x}", hash[0], hash[1] >> 4)
    );
    assert_eq!(created["never_expires"], false);
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let row = client_secrets::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.secret_hash, oauth_server::secret::hash(SUPPLIED));

    assert_eq!(
        client_credentials(&f, "deployer", SUPPLIED).await,
        StatusCode::OK
    );
    assert_eq!(
        client_credentials(&f, "deployer", &SUPPLIED.replace('Z', "Y")).await,
        StatusCode::UNAUTHORIZED
    );

    let app_id: Uuid = row.application_id;
    let events = audited(&f.db, "application.secret_add", app_id).await;
    let details = &events[0];
    assert_eq!(details["caller_supplied"], true, "{details}");
    assert_eq!(details["never_expires"], false);
    assert!(!details.to_string().contains(SUPPLIED));

    // 64 hex digits (the documented `openssl rand -hex 32`) work too.
    let (st, created) = post(&f, &token, &path, json!({ "secret": SUPPLIED_HEX })).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert!(!created.to_string().contains(SUPPLIED_HEX));
    assert_eq!(
        client_credentials(&f, "deployer", SUPPLIED_HEX).await,
        StatusCode::OK
    );

    // Generated secrets are still returned once.
    let (st, generated) = post(&f, &token, &path, json!({})).await;
    assert_eq!(st, StatusCode::CREATED);
    let value = generated["secret"].as_str().unwrap();
    assert_eq!(
        client_credentials(&f, "deployer", value).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn non_expiring_secrets_follow_the_tenant_policy() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = new_app(&f, &token, "infra").await;
    let never = json!({ "never_expires": true });

    let (st, body) = post(&f, &token, &path, never.clone()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");

    // Only a Global Admin changes the policy.
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/settings",
        Some(&token),
        Some(&json!({ "allow_non_expiring_secrets": true })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let ga = user_with_roles(
        &f.db,
        f.tenant.id,
        "ga@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    let ga_token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let (st, settings) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/settings",
        Some(&ga_token),
        Some(&json!({ "allow_non_expiring_secrets": true })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{settings}");
    assert_eq!(settings["allow_non_expiring_secrets"], true);

    let both = json!({ "never_expires": true, "expires_in_days": 30 });
    let (st, _) = post(&f, &token, &path, both).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, created) = post(&f, &token, &path, never.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert_eq!(created["expires_at"], Value::Null);
    assert_eq!(created["never_expires"], true);
    let row = client_secrets::Entity::find_by_id(
        created["id"].as_str().unwrap().parse::<Uuid>().unwrap(),
    )
    .one(&f.db)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.expires_at, None);
    let events = audited(&f.db, "application.secret_add", row.application_id).await;
    assert_eq!(events[0]["never_expires"], true, "{events:?}");

    // Switched off while a create is in flight (authenticated with the
    // policy still on): the create waits on the tenant row and is refused.
    let off = f.db.begin().await.unwrap();
    off.execute_unprepared(&format!(
        "UPDATE tenants SET allow_non_expiring_secrets = false WHERE id = '{}'",
        f.tenant.id
    ))
    .await
    .unwrap();
    let commit_later = async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        off.commit().await.unwrap();
    };
    let ((st, body), ()) = tokio::join!(post(&f, &token, &path, never), commit_later);
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn a_supplied_secret_with_form_reserved_characters_works_when_encoded() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let path = new_app(&f, &token, "deployer").await;
    let value = "2fWH6CRxNI9OZg3nSFittXX4ugYKS+tHSKM8+Qqf7/I=";
    let (st, created) = post(&f, &token, &path, json!({ "secret": value })).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");

    // RFC 6749 §2.3.1: Basic credentials are form-urlencoded first.
    let encoded: String = form_urlencoded::byte_serialize(value.as_bytes()).collect();
    assert_eq!(
        client_credentials(&f, "deployer", &encoded).await,
        StatusCode::OK
    );
    // Sent raw, `+` decodes to a space: the documented client pitfall.
    assert_eq!(
        client_credentials(&f, "deployer", value).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_system_admin_sets_the_policy_of_another_tenant() {
    let f = Fixture::new().await;
    let opts = bootstrap::Options {
        admin_email: Some("root@example.com".into()),
        ..Default::default()
    };
    bootstrap::run(&f.db, &f.config, &opts).await.unwrap();
    let system = directory::find_system_tenant(&f.db).await.unwrap().unwrap();
    let root = directory::find_user_by_email(&f.db, system.id, "root@example.com")
        .await
        .unwrap()
        .unwrap();
    let root_token = mint_user_token(&f.db, &f.config, &system, &root).await;
    let tenant_path = common::at("system", &format!("/api/v1/tenants/{}", f.tenant.slug));
    let allow = json!({ "allow_non_expiring_secrets": true });

    // A tenant admin's token isn't a system admin's.
    let token = app_admin_token(&f).await;
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &tenant_path,
        Some(&token),
        Some(&allow),
    )
    .await;
    assert_ne!(st, StatusCode::OK);

    let (st, updated) = call(
        &f.app,
        Method::PATCH,
        &tenant_path,
        Some(&root_token),
        Some(&allow),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{updated}");
    assert_eq!(updated["allow_non_expiring_secrets"], true);
    let row = tenants::Entity::find_by_id(f.tenant.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(row.allow_non_expiring_secrets);
    // Logged in both tenants, naming the field.
    let events = audited(&f.db, "tenant.update", f.tenant.id).await;
    assert_eq!(events.len(), 2, "{events:?}");
    for details in &events {
        assert_eq!(details["fields"], json!(["allow_non_expiring_secrets"]));
    }

    // The tenant's app admin can now create a non-expiring secret; an
    // unchanged repeat is not audited again.
    let path = new_app(&f, &token, "infra").await;
    let (st, created) = post(&f, &token, &path, json!({ "never_expires": true })).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &tenant_path,
        Some(&root_token),
        Some(&allow),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(audited(&f.db, "tenant.update", f.tenant.id).await.len(), 2);
}
