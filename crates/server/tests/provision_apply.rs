// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply`: one tenant file applied idempotently in one transaction.

mod common;

use common::flow::{Fixture, PASSWORD};
use entity::{
    app_required_permissions, app_role_assignments, app_scopes, applications, audit_events,
    consent_grants, directory_role_assignments, enums::ActorType, group_members, groups,
    identity_providers, users,
};
use oauth_server::{
    directory::{self, password},
    oidc::assignment,
    provision::{self, Options, Report},
};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

const IDP_SECRET: &str = "upstream-client-secret";

fn env(name: &str) -> Option<String> {
    match name {
        "OAUTH_APPLY_ALICE_PASSWORD" | "OAUTH_APPLY_DEV_PASSWORD" => Some(PASSWORD.into()),
        "OAUTH_APPLY_IDP_SECRET" | "OAUTH_APPLY_CORP_SSO_SECRET" | "OAUTH_APPLY_GOOGLE_SECRET" => {
            Some(IDP_SECRET.into())
        }
        _ => None,
    }
}

pub const FULL: &str = r"
tenant: contoso
users:
  - email: alice@example.com
    display_name: Alice
    password_env: OAUTH_APPLY_ALICE_PASSWORD
  - email: bob@example.com
    display_name: Bob
  - email: carol@example.com
    display_name: Carol
    password_env: OAUTH_APPLY_ALICE_PASSWORD
    must_change_password: false
groups:
  - display_name: Engineers
    description: Builds things
    members: [alice@example.com, ann@example.com]
identity_providers:
  - name: Upstream
    issuer: https://login.upstream.example
    client_id: oauth-upstream
    client_secret_env: OAUTH_APPLY_IDP_SECRET
    email_domains: [upstream.example]
  - name: GitHub
    kind: github
    client_id: gh-client
    client_secret_env: OAUTH_APPLY_IDP_SECRET
  - name: Google
    kind: google
    client_id: google-client
    hosted_domain: example.com
    trust_upstream_email: true
applications:
  - client_id: inventory-api
    display_name: Inventory API
    identifier_uri: api://inventory-api
    groups_claim_format: name
    assignment_required: true
    scopes:
      - { value: Inventory.Read, description: Read stock }
      - { value: Inventory.Write, admin_consent_required: true }
    roles:
      - { value: Inventory.Admin, display_name: Inventory admin, allowed_member_types: [user] }
      - { value: Inventory.Sync, display_name: Sync, allowed_member_types: [application] }
  - client_id: inventory-web
    display_name: Inventory Web
    redirect_uris: [https://inventory.example/cb]
    web_origins: [https://inventory.example]
    mfa_policy: required
    required_permissions:
      - { resource: inventory-api, type: delegated, value: Inventory.Read }
      - { resource: inventory-api, type: delegated, value: Inventory.Write }
      - { resource: inventory-api, type: application, value: Inventory.Sync }
directory_roles:
  - { user: alice@example.com, role: UserAdmin }
role_assignments:
  - { resource: inventory-api, role: Inventory.Admin, group: Engineers }
  - { resource: inventory-api, role: Inventory.Admin, user: bob@example.com }
admin_consents:
  - { client: inventory-web, resource: inventory-api }
";

async fn apply(f: &Fixture, yaml: &str, dry_run: bool) -> anyhow::Result<Report> {
    let spec = provision::parse(yaml)?;
    provision::run(&f.db, &f.config, &spec, &Options { dry_run }, &env).await
}

async fn app(f: &Fixture, client_id: &str) -> Option<applications::Model> {
    applications::Entity::find()
        .filter(applications::Column::TenantId.eq(f.tenant.id))
        .filter(applications::Column::ClientId.eq(client_id))
        .one(&f.db)
        .await
        .unwrap()
}

async fn user(f: &Fixture, email: &str) -> Option<users::Model> {
    directory::find_user_by_email(&f.db, f.tenant.id, email)
        .await
        .unwrap()
}

async fn apply_events(f: &Fixture) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .filter(audit_events::Column::ActorType.eq(ActorType::Apply))
        .count(&f.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_full_file_applies_once_then_is_up_to_date() {
    let f = Fixture::new().await;
    let report = apply(&f, FULL, false).await.unwrap();
    for line in [
        "+ user alice@example.com",
        "+ group Engineers",
        "+ member ann@example.com of Engineers",
        "+ identity provider Upstream",
        "+ application inventory-api",
        "+ scope inventory-api/Inventory.Write",
        "+ role inventory-api/Inventory.Sync",
        "+ required permission inventory-web -> inventory-api application Inventory.Sync",
        "+ directory role UserAdmin of alice@example.com",
        "+ admin consent inventory-web -> inventory-api: Inventory.Read Inventory.Write",
    ] {
        assert!(
            report.changes.iter().any(|c| c == line),
            "{line}: {report:#?}"
        );
    }
    let events = apply_events(&f).await;
    assert_eq!(events, report.changes.len() as u64);

    let alice = user(&f, "alice@example.com").await.unwrap();
    // An initial password is temporary unless the file says otherwise.
    assert!(alice.managed && alice.must_change_password);
    let carol = user(&f, "carol@example.com").await.unwrap();
    assert!(!carol.must_change_password);
    assert!(
        !user(&f, "bob@example.com")
            .await
            .unwrap()
            .must_change_password
    );
    assert!(
        password::verify(PASSWORD, alice.password_hash.as_deref().unwrap())
            .await
            .unwrap()
    );
    assert!(
        user(&f, "bob@example.com")
            .await
            .unwrap()
            .password_hash
            .is_none()
    );
    assert!(!user(&f, "ann@example.com").await.unwrap().managed);

    let web = app(&f, "inventory-web").await.unwrap();
    let api = app(&f, "inventory-api").await.unwrap();
    assert!(web.managed);
    assert_eq!(web.redirect_uris, ["https://inventory.example/cb"]);
    assert_eq!(web.mfa_policy, entity::enums::AppMfaPolicy::Required);
    assert_eq!(
        api.groups_claim_format,
        entity::enums::GroupsClaimFormat::Name
    );
    let grant = consent_grants::Entity::find()
        .filter(consent_grants::Column::ClientApplicationId.eq(web.id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(grant.managed && grant.user_id.is_none());
    assert_eq!(grant.scopes, ["Inventory.Read", "Inventory.Write"]);
    // Admin consent's app role + the two explicit assignments.
    let assignments = app_role_assignments::Entity::find()
        .filter(app_role_assignments::Column::ResourceApplicationId.eq(api.id))
        .all(&f.db)
        .await
        .unwrap();
    assert_eq!(assignments.len(), 3);
    assert!(assignments.iter().all(|a| a.managed));
    assert!(
        assignments
            .iter()
            .any(|a| a.client_application_id == Some(web.id))
    );
    assert!(api.assignment_required && !web.assignment_required);
    let idp_named = async |name: &str| {
        identity_providers::Entity::find()
            .filter(identity_providers::Column::TenantId.eq(f.tenant.id))
            .filter(identity_providers::Column::Name.eq(name))
            .one(&f.db)
            .await
            .unwrap()
            .unwrap()
    };
    let idp = idp_named("Upstream").await;
    assert!(idp.managed && idp.client_secret_sealed.is_some());
    assert_eq!(idp.kind, entity::enums::IdpKind::Oidc);
    // Presets get their kind's defaults, like a create through the API.
    let github = idp_named("GitHub").await;
    assert_eq!(github.kind, entity::enums::IdpKind::Github);
    assert_eq!(github.issuer, "https://github.com");
    assert!(github.client_secret_sealed.is_some());
    let google = idp_named("Google").await;
    assert_eq!(google.kind, entity::enums::IdpKind::Google);
    assert_eq!(google.hosted_domain.as_deref(), Some("example.com"));
    assert!(google.trust_upstream_email);
    let members = group_members::Entity::find()
        .filter(group_members::Column::TenantId.eq(f.tenant.id))
        .filter(group_members::Column::Managed.eq(true))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(members, 2);

    // Idempotent: nothing changes, nothing is audited, the secret stays.
    let again = apply(&f, FULL, false).await.unwrap();
    assert!(again.changes.is_empty(), "{again:#?}");
    assert!(again.render().contains("up to date"));
    assert_eq!(apply_events(&f).await, events);
    let idp2 = identity_providers::Entity::find_by_id(idp.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(idp2.client_secret_sealed, idp.client_secret_sealed);
}

#[tokio::test]
async fn dry_run_reports_the_diff_and_writes_nothing() {
    let f = Fixture::new().await;
    let report = apply(&f, FULL, true).await.unwrap();
    assert!(report.dry_run);
    assert!(report.changes.len() > 10);
    assert!(report.render().contains("nothing was written"));
    assert!(app(&f, "inventory-api").await.is_none());
    assert!(user(&f, "alice@example.com").await.is_none());
    assert_eq!(apply_events(&f).await, 0);
    // And the real apply finds the same changes.
    let real = apply(&f, FULL, false).await.unwrap();
    assert_eq!(real.changes, report.changes);
}

/// The second file drops bob, a scope, the web app (with its permissions
/// and consent), a membership and the IdP, and adopts the fixture's
/// `web-app`; things apply never managed stay.
const SMALLER: &str = r"
tenant: contoso
users:
  - { email: alice@example.com, display_name: Alice Liddell }
groups:
  - display_name: engineers
    members: [alice@example.com]
applications:
  - client_id: inventory-api
    display_name: Inventory API
    scopes:
      - { value: Inventory.Read, description: Read stock }
    roles:
      - { value: Inventory.Admin, display_name: Inventory admin, allowed_member_types: [user] }
  - client_id: web-app
    display_name: Contoso Web
role_assignments:
  - { resource: inventory-api, role: Inventory.Admin, group: Engineers }
";

#[tokio::test]
async fn only_managed_objects_are_deleted() {
    let f = Fixture::new().await;
    apply(&f, FULL, false).await.unwrap();
    let api = app(&f, "inventory-api").await.unwrap();
    // Added by an administrator, not by apply.
    common::seed::add_scope(&f.db, &api, "Inventory.Audit", false).await;

    let report = apply(&f, SMALLER, false).await.unwrap();
    for line in [
        "- user bob@example.com",
        "- scope inventory-api/Inventory.Write",
        "- application inventory-web",
        "- member ann@example.com of engineers",
        "- identity provider Upstream",
        "- directory role UserAdmin of alice@example.com",
        "- role assignment inventory-api/Inventory.Admin -> user bob@example.com",
        "~ user alice@example.com: display_name: 'Alice' -> 'Alice Liddell'",
        "~ application web-app: display_name: 'web-app app' -> 'Contoso Web', adopted",
    ] {
        assert!(
            report.changes.iter().any(|c| c == line),
            "{line}: {report:#?}"
        );
    }
    assert!(user(&f, "bob@example.com").await.is_none());
    assert!(user(&f, "ann@example.com").await.is_some());
    assert!(app(&f, "inventory-web").await.is_none());
    assert!(app(&f, "orders").await.is_some_and(|o| !o.managed));
    let scopes: Vec<String> = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(api.id))
        .all(&f.db)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.value)
        .collect();
    assert_eq!(scopes.len(), 2);
    assert!(scopes.contains(&"Inventory.Audit".to_owned()));
    let web = app(&f, "web-app").await.unwrap();
    assert!(web.managed);
    assert_eq!(web.display_name, "Contoso Web");
    assert_eq!(
        app_required_permissions::Entity::find()
            .filter(app_required_permissions::Column::Managed.eq(true))
            .count(&f.db)
            .await
            .unwrap(),
        0
    );
    let roles = directory_role_assignments::Entity::find()
        .filter(directory_role_assignments::Column::TenantId.eq(f.tenant.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(roles, 0, "alice's UserAdmin role is no longer declared");
    // The fixture's own group, never managed, stays.
    assert!(
        groups::Entity::find()
            .filter(groups::Column::Id.eq(f.group))
            .one(&f.db)
            .await
            .unwrap()
            .is_some()
    );

    // Adopted objects are managed: dropping them from the file deletes them.
    let empty = apply(&f, "tenant: contoso\n", false).await.unwrap();
    assert!(empty.changes.iter().any(|c| c == "- application web-app"));
    assert!(app(&f, "web-app").await.is_none());
    assert!(user(&f, "alice@example.com").await.is_none());
    assert!(app(&f, "orders").await.is_some());
}

#[tokio::test]
async fn the_documented_example_applies() {
    let f = Fixture::new().await;
    let example = include_str!("../../../docs/examples/tenant.yaml");
    let report = apply(&f, example, false).await.unwrap();
    assert!(report.changes.len() > 20, "{report:#?}");
    assert!(apply(&f, example, false).await.unwrap().changes.is_empty());
    // `inventory-web` requires assignment: an Engineers member may sign in,
    // a user outside the group may not.
    let web = app(&f, "inventory-web").await.unwrap();
    let dev = user(&f, "dev@contoso.example").await.unwrap();
    let ops = user(&f, "ops@contoso.example").await.unwrap();
    let may_use = |id| assignment::user_may_use(&f.db, f.tenant.id, id, &web, None);
    assert!(may_use(dev.id).await.unwrap());
    assert!(!may_use(ops.id).await.unwrap());
}
