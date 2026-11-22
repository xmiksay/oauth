// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply` refusals: any error leaves the tenant exactly as it was.

mod common;

use common::flow::Fixture;
use entity::{applications, audit_events, users};
use oauth_server::provision::{self, Options, Report};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter};

fn env(name: &str) -> Option<String> {
    match name {
        "OAUTH_APPLY_IDP_SECRET" => Some("s3cret-value".into()),
        "OAUTH_APPLY_SHORT" => Some("short".into()),
        _ => None,
    }
}

async fn apply(f: &Fixture, yaml: &str) -> anyhow::Result<Report> {
    let spec = provision::parse(yaml)?;
    provision::run(&f.db, &f.config, &spec, &Options { dry_run: false }, &env).await
}

/// The whole error chain, as the CLI prints it.
async fn refused(f: &Fixture, yaml: &str) -> String {
    format!("{:#}", apply(f, yaml).await.unwrap_err())
}

async fn counts(f: &Fixture) -> (u64, u64, u64) {
    let apps = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(f.tenant.id))
        .count(&f.db)
        .await
        .unwrap();
    let users = users::Entity::find()
        .filter(users::Column::TenantId.eq(f.tenant.id))
        .count(&f.db)
        .await
        .unwrap();
    let events = audit_events::Entity::find().count(&f.db).await.unwrap();
    (apps, users, events)
}

#[tokio::test]
async fn an_invalid_object_rolls_back_the_whole_file() {
    let f = Fixture::new().await;
    let before = counts(&f).await;
    let err = refused(
        &f,
        r"
tenant: contoso
users:
  - { email: new@example.com, display_name: New }
applications:
  - { client_id: fine, display_name: Fine }
  - { client_id: broken, display_name: Broken, redirect_uris: [not-a-uri] }
",
    )
    .await;
    assert!(err.contains("application `broken`"), "{err}");
    assert!(err.contains("redirect URI"), "{err}");
    assert_eq!(counts(&f).await, before);
}

#[tokio::test]
async fn references_and_rules_are_checked() {
    let f = Fixture::new().await;
    let before = counts(&f).await;
    for (yaml, expected) in [
        ("tenant: nowhere\n", "tenant `nowhere` not found"),
        (
            "tenant: contoso\nusers:\n  - { email: a@example.com, display_name: A, password_env: OAUTH_APPLY_MISSING }\n",
            "`OAUTH_APPLY_MISSING`",
        ),
        (
            "tenant: contoso\nusers:\n  - { email: a@example.com, display_name: A, password_env: OAUTH_APPLY_SHORT }\n",
            "password must be",
        ),
        (
            "tenant: contoso\napplications:\n  - { client_id: management-api, display_name: X }\n",
            "built-in",
        ),
        (
            "tenant: contoso\napplications:\n  - { client_id: spa-app, display_name: SPA, client_type: confidential }\n",
            "client_type can't be changed",
        ),
        (
            "tenant: contoso\ngroups:\n  - { display_name: G, members: [ghost@example.com] }\n",
            "user `ghost@example.com` not found",
        ),
        (
            "tenant: contoso\nrole_assignments:\n  - { resource: orders, role: Nope, user: ann@example.com }\n",
            "`orders` has no app role `Nope`",
        ),
        (
            "tenant: contoso\nadmin_consents:\n  - { client: web-app, resource: ledger, scopes: [Ledger.Write] }\n",
            "is not a required scope",
        ),
        (
            "tenant: contoso\nidentity_providers:\n  - { name: X, issuer: https://x.example, client_id: x, client_secret_env: OAUTH_MASTER_KEY }\n",
            "must be named `OAUTH_APPLY_`",
        ),
        (
            "tenant: contoso\ndirectory_roles:\n  - { user: ann@example.com, role: Emperor }\n",
            "role must be",
        ),
        (
            "tenant: contoso\napplications:\n  - client_id: x1\n    display_name: X\n    scopes: [{ value: openid }]\n",
            "openid",
        ),
    ] {
        let err = refused(&f, yaml).await;
        assert!(err.contains(expected), "{yaml}: {err}");
    }
    assert_eq!(counts(&f).await, before);
}

const IDP: &str = r"
tenant: contoso
identity_providers:
  - name: Upstream
    issuer: https://login.upstream.example
    client_id: oauth-upstream
    client_secret_env: OAUTH_APPLY_IDP_SECRET
";

#[tokio::test]
async fn identity_providers_are_never_repointed() {
    let f = Fixture::new().await;
    apply(&f, IDP).await.unwrap();
    let moved = IDP.replace("login.upstream.example", "evil.example");
    let err = refused(&f, &moved).await;
    assert!(err.contains("`issuer` repoints"), "{err}");
    let renamed_client = IDP.replace("client_id: oauth-upstream", "client_id: other");
    assert!(
        refused(&f, &renamed_client)
            .await
            .contains("`client_id` repoints")
    );
    // Other settings still apply.
    let scoped = format!("{IDP}    scopes: [openid, email]\n");
    let report = apply(&f, &scoped).await.unwrap();
    assert_eq!(
        report.changes,
        [
            "~ identity provider Upstream: scopes: ARRAY ['openid','email','profile'] -> ARRAY ['openid','email']"
        ]
    );
}

#[tokio::test]
async fn the_last_global_admin_is_kept() {
    let f = Fixture::new().await;
    let with_admin = r"
tenant: contoso
users:
  - { email: root@example.com, display_name: Root }
directory_roles:
  - { user: root@example.com, role: GlobalAdmin }
";
    apply(&f, with_admin).await.unwrap();
    let without_role =
        "tenant: contoso\nusers:\n  - { email: root@example.com, display_name: Root }\n";
    let err = refused(&f, without_role).await;
    assert!(err.contains("last enabled Global Admin"), "{err}");
    let disabled = with_admin.replace(
        "display_name: Root }",
        "display_name: Root, disabled: true }",
    );
    assert!(
        refused(&f, &disabled)
            .await
            .contains("last enabled Global Admin")
    );
    assert!(
        refused(&f, "tenant: contoso\n")
            .await
            .contains("last enabled Global Admin")
    );
}

#[tokio::test]
async fn a_global_admin_can_be_swapped_in_one_apply() {
    let f = Fixture::new().await;
    apply(
        &f,
        r"
tenant: contoso
users:
  - { email: root@example.com, display_name: Root }
directory_roles:
  - { user: root@example.com, role: GlobalAdmin }
",
    )
    .await
    .unwrap();
    // The end state has an enabled Global Admin: B is promoted in the same
    // run that disables root and drops root's role.
    let report = apply(
        &f,
        r"
tenant: contoso
users:
  - { email: root@example.com, display_name: Root, disabled: true }
  - { email: b@example.com, display_name: B }
directory_roles:
  - { user: b@example.com, role: GlobalAdmin }
",
    )
    .await
    .unwrap();
    for line in [
        "~ user root@example.com: disabled: FALSE -> TRUE",
        "+ directory role GlobalAdmin of b@example.com",
        "- directory role GlobalAdmin of root@example.com",
    ] {
        assert!(report.changes.iter().any(|c| c == line), "{report:#?}");
    }
    // Disabling b now leaves nobody.
    let err = refused(
        &f,
        r"
tenant: contoso
users:
  - { email: root@example.com, display_name: Root, disabled: true }
  - { email: b@example.com, display_name: B, disabled: true }
directory_roles:
  - { user: b@example.com, role: GlobalAdmin }
",
    )
    .await;
    assert!(err.contains("disabling user `b@example.com`"), "{err}");
    assert!(err.contains("last enabled Global Admin"), "{err}");
}

#[tokio::test]
async fn references_to_what_the_file_deletes_are_refused() {
    let f = Fixture::new().await;
    apply(
        &f,
        r"
tenant: contoso
users:
  - { email: bob@example.com, display_name: Bob }
groups:
  - { display_name: Eng }
applications:
  - client_id: api1
    display_name: API
    scopes: [{ value: Api.Read }]
",
    )
    .await
    .unwrap();
    let before = counts(&f).await;
    for (yaml, expected) in [
        (
            "tenant: contoso\ngroups:\n  - { display_name: Eng, members: [BOB@example.com] }\n",
            "references user `BOB@example.com`, which this file deletes",
        ),
        (
            "tenant: contoso\nusers:\n  - { email: bob@example.com, display_name: Bob }\nrole_assignments:\n  - { resource: orders, role: Orders.Approver, group: eng }\n",
            "references group `eng`, which this file deletes",
        ),
        (
            "tenant: contoso\napplications:\n  - client_id: web-app\n    display_name: Web\n    required_permissions: [{ resource: api1, type: delegated, value: Api.Read }]\n",
            "references application `api1`, which this file deletes",
        ),
    ] {
        let err = refused(&f, yaml).await;
        assert!(err.contains(expected), "{yaml}: {err}");
    }
    assert_eq!(counts(&f).await, before);
}

#[tokio::test]
async fn an_identity_providers_kind_is_fixed() {
    let f = Fixture::new().await;
    apply(&f, IDP).await.unwrap();
    let github = IDP.replace("    issuer:", "    kind: github\n    issuer:");
    let err = refused(&f, &github).await;
    assert!(err.contains("kind can't be changed"), "{err}");
}

/// A dry run against `db` (no tenant fixture: the schema may be missing).
async fn dry_run_error(
    db: &sea_orm::DatabaseConnection,
    config: &oauth_server::config::Config,
) -> String {
    let spec = provision::parse("tenant: contoso\n").unwrap();
    let opts = Options { dry_run: true };
    let err = provision::run(db, config, &spec, &opts, &env).await;
    format!("{:#}", err.unwrap_err())
}

#[tokio::test]
async fn an_unmigrated_database_is_refused_before_any_write() {
    let pg = common::start_postgres().await;
    let db = oauth_server::db::connect(&pg.url).await.unwrap();
    let config = common::test_config(&pg.url, common::PUBLIC_URL);
    let err = dry_run_error(&db, &config).await;
    assert!(err.contains("no schema yet"), "{err}");
    assert!(err.contains("oauth bootstrap"), "{err}");
    // Still nothing: the check doesn't create the migrations table.
    let err = dry_run_error(&db, &config).await;
    assert!(err.contains("no schema yet"), "{err}");

    oauth_server::db::migrate(&db).await.unwrap();
    db.execute_unprepared(
        "DELETE FROM seaql_migrations WHERE version = 'm20261122_000022_provisioning'",
    )
    .await
    .unwrap();
    let err = dry_run_error(&db, &config).await;
    assert!(err.contains("1 migration(s) behind"), "{err}");
}
