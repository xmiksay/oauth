// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The client secret expiry warning job (#46): who is warned, once, and
//! that a secret nobody could be warned about stays pending.
mod common;

use chrono::{DateTime, Duration, FixedOffset};
use common::{
    flow::Fixture,
    mail::only_to,
    mgmt::user_with_roles,
    seed::{add_app, add_secret},
};
use entity::{
    client_secrets,
    enums::{AccessTokenFormat, ClientType, DirectoryRole, SigningAlg},
    outbox, tenants,
};
use oauth_server::{
    directory::{self, NewTenant},
    jobs::secret_expiry,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
};
use uuid::Uuid;

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

async fn notified(f: &Fixture, id: Uuid) -> bool {
    client_secrets::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .expiry_notified_at
        .is_some()
}

async fn run(f: &Fixture, at: DateTime<FixedOffset>) -> Option<usize> {
    secret_expiry::run_once(&f.db, &f.config, at).await.unwrap()
}

async fn set_disabled(f: &Fixture, tenant: &tenants::Model, disabled: bool) {
    let mut row: tenants::ActiveModel = tenant.clone().into();
    row.disabled = Set(disabled);
    row.update(&f.db).await.unwrap();
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
    assert_eq!(run(&f, now).await, Some(1));
    assert_eq!(run(&f, now).await, Some(0), "warned once");
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
    assert_eq!(run(&f, now + Duration::days(7)).await, Some(1));
    assert!(notified(&f, ledger).await);
    assert_eq!(run(&f, now + Duration::days(30)).await, Some(0));
}

#[tokio::test]
async fn a_secret_stays_pending_until_an_admin_can_be_warned() {
    let f = Fixture::with_email().await;
    let web = secret_of(&f, f.web.id).await;
    expire_in(&f, web, Duration::days(10)).await;
    let now = chrono::Utc::now().fixed_offset();

    // An unverified Global Admin can't be emailed: nothing is marked.
    let ga = user_with_roles(
        &f.db,
        f.tenant.id,
        "ga@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    assert_eq!(run(&f, now).await, Some(0));
    assert!(!notified(&f, web).await);
    assert_eq!(f.outbox_rows().await, 0);

    // A disabled tenant isn't warned either, even with an eligible admin.
    f.verify(&ga).await;
    set_disabled(&f, &f.tenant, true).await;
    assert_eq!(run(&f, now).await, Some(0));
    assert!(!notified(&f, web).await);

    // Re-enabled with a verified admin: the pending warning goes out once.
    set_disabled(&f, &f.tenant, false).await;
    assert_eq!(run(&f, now + Duration::days(1)).await, Some(1));
    assert!(notified(&f, web).await);
    let mails = f.deliver().await;
    assert_eq!(mails.len(), 1);
    only_to(&mails, "ga@example.com");
    assert_eq!(run(&f, now + Duration::days(2)).await, Some(0));
}

#[tokio::test]
async fn warnings_go_only_to_the_secrets_own_tenant() {
    let f = Fixture::with_email().await;
    let other = directory::create_tenant(
        &f.db,
        &f.config,
        NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let ours = user_with_roles(
        &f.db,
        f.tenant.id,
        "ga@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    f.verify(&ours).await;
    let theirs = user_with_roles(
        &f.db,
        other.id,
        "ga@fabrikam.example",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    f.verify(&theirs).await;
    let deployer = add_app(
        &f.db,
        other.id,
        "deployer",
        ClientType::Confidential,
        None,
        AccessTokenFormat::Jwt,
        SigningAlg::Rs256,
    )
    .await;
    add_secret(&f.db, &deployer).await;
    let theirs_secret = secret_of(&f, deployer.id).await;
    let web = secret_of(&f, f.web.id).await;
    expire_in(&f, web, Duration::days(5)).await;
    expire_in(&f, theirs_secret, Duration::days(6)).await;

    let now = chrono::Utc::now().fixed_offset();
    assert_eq!(run(&f, now).await, Some(2));
    let mails = f.deliver().await;
    assert_eq!(mails.len(), 2);
    let ours_mail = only_to(&mails, "ga@example.com");
    assert!(
        ours_mail.body.contains("Client ID: web-app"),
        "{}",
        ours_mail.body
    );
    let theirs_mail = only_to(&mails, "ga@fabrikam.example");
    assert!(
        theirs_mail.body.contains("Client ID: deployer"),
        "{}",
        theirs_mail.body
    );
    assert!(!theirs_mail.body.contains("web-app"));
}

#[tokio::test]
async fn without_email_the_job_waits() {
    let f = Fixture::new().await;
    let web = secret_of(&f, f.web.id).await;
    expire_in(&f, web, Duration::days(1)).await;
    let now = chrono::Utc::now().fixed_offset();
    assert_eq!(run(&f, now).await, None);
    assert!(!notified(&f, web).await);
}
