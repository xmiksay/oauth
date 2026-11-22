// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply`'s security-relevant side effects: the tokens a change
//! revokes or keeps, and what deleting an identity provider takes along.

mod common;

use axum::http::StatusCode;
use common::{flow::Fixture, seed::insert};
use entity::{
    audit_events, group_members, groups, identity_providers, sessions, user_identities, users,
};
use oauth_server::provision::{self, Options, Report};
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use uuid::Uuid;

fn env(name: &str) -> Option<String> {
    (name == "OAUTH_APPLY_IDP_SECRET").then(|| "upstream-client-secret".into())
}

async fn apply(f: &Fixture, yaml: &str) -> Report {
    let spec = provision::parse(yaml).unwrap();
    provision::run(&f.db, &f.config, &spec, &Options { dry_run: false }, &env)
        .await
        .unwrap()
}

async fn refresh_token(f: &Fixture, scope: &str) -> String {
    let (_, tokens) = f.web_tokens(scope, "ann@example.com").await;
    tokens["refresh_token"].as_str().unwrap().to_owned()
}

/// Refreshes; returns the rotated token, or `None` when the family is
/// revoked.
async fn renew(f: &Fixture, token: &str) -> Option<String> {
    let (st, body) = f.refresh(token, None).await;
    if st == StatusCode::OK {
        return Some(body["refresh_token"].as_str().unwrap().to_owned());
    }
    assert_eq!(body["error"], "invalid_grant", "{body}");
    None
}

fn consent(scopes: &str) -> String {
    format!(
        r"
tenant: contoso
applications:
  - client_id: web-app
    display_name: Web
    required_permissions:
      - {{ resource: orders, type: delegated, value: Orders.Read }}
      - {{ resource: orders, type: delegated, value: Orders.Write }}
admin_consents:
  - {{ client: web-app, resource: orders, scopes: [{scopes}] }}
"
    )
}

#[tokio::test]
async fn widening_a_consent_keeps_tokens_and_narrowing_revokes_them() {
    let f = Fixture::new().await;
    apply(&f, &consent("Orders.Read")).await;
    let token = refresh_token(&f, "offline_access api://orders/Orders.Read").await;

    let widened = apply(&f, &consent("Orders.Read, Orders.Write")).await;
    assert_eq!(
        widened.changes,
        [
            "~ admin consent web-app -> orders: scopes: ARRAY ['Orders.Read'] -> ARRAY ['Orders.Read','Orders.Write']"
        ]
    );
    let token = renew(&f, &token).await.expect("widening keeps the family");

    let narrowed = apply(&f, &consent("Orders.Write")).await;
    assert_eq!(
        narrowed.changes,
        [
            "- admin consent web-app -> orders",
            "+ admin consent web-app -> orders: Orders.Write",
        ]
    );
    assert_eq!(renew(&f, &token).await, None);
}

const ORDERS: &str = r"
tenant: contoso
applications:
  - client_id: orders
    display_name: Orders
    scopes:
      - { value: Orders.Read }
";

#[tokio::test]
async fn removing_a_managed_scope_revokes_the_tokens_carrying_it() {
    let f = Fixture::new().await;
    let both = format!("{ORDERS}      - {{ value: Orders.Write }}\n");
    apply(&f, &both).await;
    let read_only = refresh_token(&f, "offline_access api://orders/Orders.Read").await;
    let with_write = refresh_token(
        &f,
        "offline_access api://orders/Orders.Read api://orders/Orders.Write",
    )
    .await;

    let report = apply(&f, ORDERS).await;
    assert_eq!(report.changes, ["- scope orders/Orders.Write"]);
    assert_eq!(renew(&f, &with_write).await, None);
    assert!(renew(&f, &read_only).await.is_some());
}

#[tokio::test]
async fn disabling_a_user_revokes_sessions_and_tokens() {
    let f = Fixture::new().await;
    let token = refresh_token(&f, "offline_access api://orders/Orders.Read").await;
    let sessions_of_ann = || {
        sessions::Entity::find()
            .filter(sessions::Column::UserId.eq(f.user.id))
            .count(&f.db)
    };
    assert_eq!(sessions_of_ann().await.unwrap(), 1);

    let report = apply(
        &f,
        "tenant: contoso\nusers:\n  - { email: ann@example.com, display_name: Ann, disabled: true }\n",
    )
    .await;
    assert_eq!(
        report.changes,
        [
            "~ user ann@example.com: display_name: 'Test User' -> 'Ann', disabled: FALSE -> TRUE, adopted"
        ]
    );
    assert_eq!(sessions_of_ann().await.unwrap(), 0);
    assert_eq!(renew(&f, &token).await, None);
}

#[tokio::test]
async fn a_padded_email_reapplies_and_a_disabled_user_is_created_disabled() {
    let f = Fixture::new().await;
    let yaml = "tenant: contoso\nusers:\n  - { email: \" zed@example.com \", display_name: Zed, disabled: true }\n";
    assert_eq!(apply(&f, yaml).await.changes, ["+ user zed@example.com"]);
    assert!(apply(&f, yaml).await.changes.is_empty(), "idempotent");
    let zed = users::Entity::find()
        .filter(users::Column::Email.eq("zed@example.com"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(zed.disabled && zed.managed);
    let event = audit_events::Entity::find()
        .filter(audit_events::Column::EventType.eq("user.create"))
        .filter(audit_events::Column::TargetId.eq(zed.id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.details["disabled"], true);
}

const IDP: &str = r"
tenant: contoso
identity_providers:
  - name: Upstream
    issuer: https://login.upstream.example
    client_id: oauth-upstream
    client_secret_env: OAUTH_APPLY_IDP_SECRET
";

const GROUPS: &str = r"
groups:
  - { display_name: Mapped }
  - display_name: Eng
";

async fn group_id(f: &Fixture, name: &str) -> Uuid {
    groups::Entity::find()
        .filter(groups::Column::TenantId.eq(f.tenant.id))
        .filter(groups::Column::DisplayName.eq(name))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .id
}

async fn membership(f: &Fixture, group: &str) -> Option<group_members::Model> {
    let group = group_id(f, group).await;
    group_members::Entity::find()
        .filter(group_members::Column::GroupId.eq(group))
        .filter(group_members::Column::UserId.eq(f.user.id))
        .one(&f.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn mapped_memberships_outlive_the_file_until_the_idp_goes() {
    let f = Fixture::new().await;
    let with_ann = format!("{IDP}{GROUPS}    members: [ann@example.com]\n");
    apply(&f, &with_ann).await;
    let idp = identity_providers::Entity::find()
        .filter(identity_providers::Column::TenantId.eq(f.tenant.id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    insert(
        &f.db,
        user_identities::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(f.tenant.id),
            user_id: Set(f.user.id),
            idp_id: Set(idp.id),
            subject: Set("upstream-sub".into()),
            ..Default::default()
        },
    )
    .await;
    // The provider's mapping also keeps ann in Eng, and only it in Mapped.
    let eng = group_id(&f, "Eng").await;
    group_members::Entity::update_many()
        .col_expr(group_members::Column::IdpId, Some(idp.id).into())
        .filter(group_members::Column::GroupId.eq(eng))
        .exec(&f.db)
        .await
        .unwrap();
    insert(
        &f.db,
        group_members::ActiveModel {
            tenant_id: Set(f.tenant.id),
            group_id: Set(group_id(&f, "Mapped").await),
            user_id: Set(f.user.id),
            manual: Set(false),
            idp_id: Set(Some(idp.id)),
            ..Default::default()
        },
    )
    .await;

    // Dropped from the file: the row stays, as the mapping's alone.
    let report = apply(&f, &format!("{IDP}{GROUPS}")).await;
    assert_eq!(report.changes, ["- member ann@example.com of Eng"]);
    let kept = membership(&f, "Eng").await.unwrap();
    assert!(!kept.manual && !kept.managed && kept.idp_id == Some(idp.id));

    // Pruning the provider takes its identities and mapped memberships.
    let report = apply(&f, &format!("tenant: contoso\n{GROUPS}")).await;
    assert_eq!(report.changes, ["- identity provider Upstream"]);
    assert!(membership(&f, "Eng").await.is_none());
    assert!(membership(&f, "Mapped").await.is_none());
    let identities = user_identities::Entity::find()
        .filter(user_identities::Column::UserId.eq(f.user.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(identities, 0);
    // The fixture's manual membership is untouched.
    assert!(
        group_members::Entity::find()
            .filter(group_members::Column::GroupId.eq(f.group))
            .one(&f.db)
            .await
            .unwrap()
            .is_some()
    );
}
