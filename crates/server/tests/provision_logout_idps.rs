// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply` and main's newer rules: back-channel logout settings and
//! notifications, and identity provider updates sharing the API's path
//! (generation bump, mapped memberships, mapping checks).

mod common;

use common::{
    backchannel::{queued, set_uri},
    flow::Fixture,
    seed::insert,
};
use entity::{
    applications, audit_events,
    enums::{ActorType, IdTokenGroups},
    group_members, groups, identity_providers, idp_group_mappings, users,
};
use oauth_server::provision::{self, Options, Report};
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

const RP: &str = "https://rp.example/bcl";
const T1: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
const T2: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

fn env(name: &str) -> Option<String> {
    (name == "OAUTH_APPLY_IDP_SECRET").then(|| "upstream-client-secret".into())
}

async fn try_apply(f: &Fixture, yaml: &str) -> anyhow::Result<Report> {
    let spec = provision::parse(yaml).unwrap();
    provision::run(&f.db, &f.config, &spec, &Options { dry_run: false }, &env).await
}

async fn apply(f: &Fixture, yaml: &str) -> Report {
    try_apply(f, yaml).await.unwrap()
}

const ANN: &str = "tenant: contoso\nusers:\n  - { email: ann@example.com, display_name: Ann }\n";

/// Ann, managed by apply, signed in to `web-app` (with a back-channel URI).
async fn managed_ann_signed_in(f: &Fixture) {
    apply(f, ANN).await;
    set_uri(f, Some(RP)).await;
    f.web_tokens("openid", "ann@example.com").await;
    assert!(queued(f).await.is_empty());
}

#[tokio::test]
async fn disabling_a_user_queues_back_channel_logouts() {
    let f = Fixture::new().await;
    managed_ann_signed_in(&f).await;
    let disabled = ANN.replace("Ann }", "Ann, disabled: true }");
    apply(&f, &disabled).await;
    let rows = queued(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].recipient, f.web.id.to_string());
}

#[tokio::test]
async fn deleting_a_user_queues_back_channel_logouts() {
    let f = Fixture::new().await;
    managed_ann_signed_in(&f).await;
    let report = apply(&f, "tenant: contoso\n").await;
    assert_eq!(report.changes, ["- user ann@example.com"]);
    assert!(
        users::Entity::find_by_id(f.user.id)
            .one(&f.db)
            .await
            .unwrap()
            .is_none()
    );
    let rows = queued(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].recipient, f.web.id.to_string());
}

async fn app(f: &Fixture, client_id: &str) -> applications::Model {
    applications::Entity::find()
        .filter(applications::Column::TenantId.eq(f.tenant.id))
        .filter(applications::Column::ClientId.eq(client_id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn back_channel_logout_and_id_token_groups_are_declarable() {
    let f = Fixture::new().await;
    let yaml = |extra: &str| {
        format!("tenant: contoso\napplications:\n  - client_id: rp\n    display_name: RP\n{extra}")
    };
    let first = yaml(
        "    backchannel_logout_uri: https://rp.example/bcl\n    \
         backchannel_logout_session_required: true\n    id_token_groups: assigned\n",
    );
    assert_eq!(apply(&f, &first).await.changes, ["+ application rp"]);
    let rp = app(&f, "rp").await;
    assert_eq!(rp.backchannel_logout_uri.as_deref(), Some(RP));
    assert!(rp.backchannel_logout_session_required);
    assert_eq!(rp.id_token_groups, IdTokenGroups::Assigned);
    assert!(apply(&f, &first).await.changes.is_empty());

    // Explicit null clears the URI; the diff names both changes.
    let second = yaml("    backchannel_logout_uri: null\n    id_token_groups: all\n");
    let changes = apply(&f, &second).await.changes;
    assert_eq!(changes.len(), 1, "{changes:?}");
    let line = &changes[0];
    assert!(line.starts_with("~ application rp: "), "{line}");
    assert!(
        line.contains("backchannel_logout_uri: 'https://rp.example/bcl' -> NULL"),
        "{line}"
    );
    assert!(
        line.contains("id_token_groups: 'assigned' -> 'all'"),
        "{line}"
    );
    let rp = app(&f, "rp").await;
    assert_eq!(rp.backchannel_logout_uri, None);
    assert_eq!(rp.id_token_groups, IdTokenGroups::All);

    // The API's validation applies (https only outside loopback dev).
    let bad = yaml("    backchannel_logout_uri: http://rp.example/bcl\n");
    assert!(try_apply(&f, &bad).await.is_err());
}

fn entra(allowed: &str) -> String {
    format!(
        r"
tenant: contoso
groups:
  - display_name: Mapped
identity_providers:
  - name: Entra
    kind: entra
    issuer: https://login.upstream.example/{{tenantid}}/v2.0
    discovery_url: https://login.upstream.example/organizations/v2.0/.well-known/openid-configuration
    client_id: oauth-upstream
    client_secret_env: OAUTH_APPLY_IDP_SECRET
    allowed_tenants: [{allowed}]
"
    )
}

async fn entra_idp(f: &Fixture) -> identity_providers::Model {
    identity_providers::Entity::find()
        .filter(identity_providers::Column::TenantId.eq(f.tenant.id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
}

/// Ann in `Mapped` through the provider's group mapping.
async fn mapped_member(f: &Fixture, idp: &identity_providers::Model) -> Uuid {
    let group = groups::Entity::find()
        .filter(groups::Column::TenantId.eq(f.tenant.id))
        .filter(groups::Column::DisplayName.eq("Mapped"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    insert(
        &f.db,
        idp_group_mappings::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(f.tenant.id),
            idp_id: Set(idp.id),
            claim: Set("roles".into()),
            value: Set("Admins".into()),
            group_id: Set(group.id),
            created_at: Set(chrono::Utc::now().fixed_offset()),
        },
    )
    .await;
    insert(
        &f.db,
        group_members::ActiveModel {
            tenant_id: Set(f.tenant.id),
            group_id: Set(group.id),
            user_id: Set(f.user.id),
            manual: Set(false),
            idp_id: Set(Some(idp.id)),
            ..Default::default()
        },
    )
    .await;
    group.id
}

async fn is_member(f: &Fixture, group: Uuid) -> bool {
    group_members::Entity::find()
        .filter(group_members::Column::GroupId.eq(group))
        .filter(group_members::Column::UserId.eq(f.user.id))
        .one(&f.db)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn narrowing_allowed_tenants_bumps_the_generation_and_drops_mapped_memberships() {
    let f = Fixture::new().await;
    apply(&f, &entra(&format!("{T1}, {T2}"))).await;
    let before = entra_idp(&f).await;
    let group = mapped_member(&f, &before).await;

    // Re-applying the same list changes nothing.
    assert!(
        apply(&f, &entra(&format!("{T1}, {T2}")))
            .await
            .changes
            .is_empty()
    );

    apply(&f, &entra(T1)).await;
    let after = entra_idp(&f).await;
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.allowed_tenants, [T1]);
    assert!(!is_member(&f, group).await);
    let event = audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .filter(audit_events::Column::ActorType.eq(ActorType::Apply))
        .filter(audit_events::Column::EventType.eq("identity_provider.update"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.details["memberships_removed"], 1);
    assert_eq!(event.details["identities_removed"], 0);
}

#[tokio::test]
async fn opening_a_mapped_provider_to_every_tenant_is_refused() {
    let f = Fixture::new().await;
    apply(&f, &entra(T1)).await;
    let idp = entra_idp(&f).await;
    let group = mapped_member(&f, &idp).await;
    let err = try_apply(&f, &entra("")).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("needs allowed_tenants"),
        "{err:#}"
    );
    // Nothing was written.
    let unchanged = entra_idp(&f).await;
    assert_eq!(unchanged.allowed_tenants, [T1]);
    assert_eq!(unchanged.generation, idp.generation);
    assert!(is_member(&f, group).await);
}
