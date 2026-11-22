// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Client secret options (#46): caller-supplied values, non-expiring
//! secrets behind the tenant policy, and the expiry warning job.
mod common;

use axum::http::{Method, StatusCode};
use chrono::Duration;
use common::{
    flow::Fixture,
    mail::only_to,
    mgmt::{app_admin_token, audited, call, mint_user_token, post, user_with_roles},
};
use entity::{client_secrets, enums::DirectoryRole, outbox};
use oauth_server::jobs::secret_expiry;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
};
use serde_json::{Value, json};
use uuid::Uuid;

const APPS: &str = "/api/v1/applications";
const SUPPLIED: &str = "Zx8pQ2vN7rT4kL9wB3mY6cH1jF5dS0aG-uE_iO";

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
    for weak in ["short", hex32, &"a".repeat(64), &format!("{SUPPLIED} x")] {
        let (st, body) = post(&f, &token, &path, json!({ "secret": weak })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(!body.to_string().contains(weak));
    }

    let (st, created) = post(&f, &token, &path, json!({ "secret": SUPPLIED })).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert!(created.get("secret").is_none(), "{created}");
    assert!(!created.to_string().contains(SUPPLIED));
    assert_eq!(created["hint"], "Zx8");
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
    let (st, created) = post(&f, &token, &path, never).await;
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
}

async fn expire_in(f: &Fixture, id: Uuid, after: Duration) {
    let row = client_secrets::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let mut row: client_secrets::ActiveModel = row.into();
    row.expires_at = Set(Some(chrono::Utc::now().fixed_offset() + after));
    row.update(&f.db).await.unwrap();
}

async fn secret_of(f: &Fixture, app_id: Uuid) -> Uuid {
    client_secrets::Entity::find()
        .filter(client_secrets::Column::ApplicationId.eq(app_id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .id
}

#[tokio::test]
async fn app_admins_are_warned_once_before_a_secret_expires() {
    let f = Fixture::with_email().await;
    let roles = [
        ("ga@example.com", DirectoryRole::GlobalAdmin, true),
        ("aa@example.com", DirectoryRole::ApplicationAdmin, true),
        ("ua@example.com", DirectoryRole::UserAdmin, true),
        (
            "unverified@example.com",
            DirectoryRole::ApplicationAdmin,
            false,
        ),
    ];
    for (email, role, verified) in roles {
        let user = user_with_roles(&f.db, f.tenant.id, email, &[role]).await;
        if verified {
            f.verify(&user).await;
        }
    }
    let web = secret_of(&f, f.web.id).await;
    let ledger = secret_of(&f, f.ledger.id).await;
    expire_in(&f, web, Duration::days(10)).await;
    expire_in(&f, ledger, Duration::days(20)).await;

    let now = chrono::Utc::now().fixed_offset();
    let run = |at| secret_expiry::run_once(&f.db, &f.config, at);
    assert_eq!(run(now).await.unwrap(), Some(1));
    assert_eq!(run(now).await.unwrap(), Some(0), "warned once");
    let queued = outbox::Entity::find()
        .filter(outbox::Column::Kind.eq("secret_expiring"))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(queued, 2);
    let mails = f.deliver().await;
    for to in ["ga@example.com", "aa@example.com"] {
        let mail = only_to(&mails, to);
        assert!(mail.subject.contains("web"), "{}", mail.subject);
        assert!(mail.body.contains("Client ID: web-app"), "{}", mail.body);
        assert!(
            mail.body
                .contains(&format!("/admin/app-registrations/{}/secrets", f.web.id))
        );
    }
    assert!(!mails.iter().any(|m| m.to == "ua@example.com"));
    assert!(!mails.iter().any(|m| m.to == "unverified@example.com"));

    // The later secret enters the window a week on; an expired one never.
    assert_eq!(run(now + Duration::days(7)).await.unwrap(), Some(1));
    let row = client_secrets::Entity::find_by_id(ledger)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(row.expiry_notified_at.is_some());
    assert_eq!(run(now + Duration::days(30)).await.unwrap(), Some(0));
}

#[tokio::test]
async fn without_email_the_job_waits() {
    let f = Fixture::new().await;
    let web = secret_of(&f, f.web.id).await;
    expire_in(&f, web, Duration::days(1)).await;
    let now = chrono::Utc::now().fixed_offset();
    assert_eq!(
        secret_expiry::run_once(&f.db, &f.config, now)
            .await
            .unwrap(),
        None
    );
    let row = client_secrets::Entity::find_by_id(web)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.expiry_notified_at, None);
}
