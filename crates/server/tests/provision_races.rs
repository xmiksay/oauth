// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply` racing a federated sign-in: apply takes the tenant's IdPs
//! before any user (the global IdP → user order), and releasing a managed
//! membership never drops one a group mapping took over meanwhile.
//!
//! The first test proves the lock order; with `idps::lock_all` in place a
//! mapping through an IdP that existed before the apply can't change a
//! membership while apply reads and releases it. The release tests below
//! therefore race a writer `lock_all` doesn't hold back — one through an IdP
//! created after it ran, or the management API deleting the row — and hold
//! the `group_members` row so apply's write blocks between its read and the
//! re-check. The adopt / keep tests race an admin deleting a declared
//! membership, and the last one an IdP the file declares created after
//! `lock_all` ran.

mod common;

use common::{backchannel::wait_for_lock_waiter, flow::Fixture};
use entity::{audit_events, group_members, groups, identity_providers, users};
use oauth_server::{
    backchannel, directory,
    federation::idps,
    provision::{self, Options, Report},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseTransaction,
    EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, Statement, TransactionTrait,
};
use uuid::Uuid;

fn env(name: &str) -> Option<String> {
    (name == "OAUTH_APPLY_IDP_SECRET").then(|| "upstream-client-secret".into())
}

const IDP: &str = "
identity_providers:
  - name: Upstream
    issuer: https://login.upstream.example
    client_id: oauth-upstream
    client_secret_env: OAUTH_APPLY_IDP_SECRET
";

async fn apply(f: &Fixture, yaml: &str) -> anyhow::Result<Report> {
    let spec = provision::parse(yaml).unwrap();
    provision::run(&f.db, &f.config, &spec, &Options { dry_run: false }, &env).await
}

#[tokio::test]
async fn apply_and_a_federated_sign_in_neither_deadlock_nor_lose_a_mapped_membership() {
    let f = Fixture::new().await;
    let before = format!(
        "tenant: contoso\nusers:\n  - {{ email: ann@example.com, display_name: Ann }}\n\
         groups:\n  - {{ display_name: Staff, members: [ann@example.com] }}\n{IDP}"
    );
    apply(&f, &before).await.unwrap();
    let ann = directory::find_user_by_email(&f.db, f.tenant.id, "ann@example.com")
        .await
        .unwrap()
        .unwrap();
    let staff = groups::Entity::find()
        .filter(groups::Column::TenantId.eq(f.tenant.id))
        .filter(groups::Column::DisplayName.eq("Staff"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let idp = identity_providers::Entity::find()
        .filter(identity_providers::Column::TenantId.eq(f.tenant.id))
        .filter(identity_providers::Column::Name.eq("Upstream"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();

    // Ann signs in through Upstream: the sign-in holds the IdP `FOR SHARE`.
    let sign_in = f.db.begin().await.unwrap();
    assert!(
        idps::lock_current(&sign_in, f.tenant.id, idp.id, idp.generation)
            .await
            .unwrap()
            .is_some()
    );
    // Meanwhile the file disables Ann and drops her from Staff.
    let after = format!(
        "tenant: contoso\nusers:\n  - {{ email: ann@example.com, display_name: Ann, disabled: true }}\n\
         groups:\n  - {{ display_name: Staff, members: [] }}\n{IDP}"
    );
    let signing_in = async {
        // Apply waits on the IdP before it locked Ann: the sign-in gets her
        // (still active) and its group mapping takes over the membership.
        wait_for_lock_waiter(&f.db).await;
        let lock = backchannel::lock_user(&sign_in, f.tenant.id, ann.id)
            .await
            .unwrap();
        assert!(lock.is_active());
        sign_in
            .execute_raw(Statement::from_sql_and_values(
                sign_in.get_database_backend(),
                "UPDATE group_members SET idp_id = $1 WHERE group_id = $2 AND user_id = $3",
                [idp.id.into(), staff.id.into(), ann.id.into()],
            ))
            .await
            .unwrap();
        sign_in.commit().await.unwrap();
    };
    let (report, ()) = tokio::join!(apply(&f, &after), signing_in);
    let report = report.unwrap();
    assert!(
        report
            .changes
            .iter()
            .any(|c| c == "- member ann@example.com of Staff"),
        "{report:#?}"
    );

    let ann = directory::find_user_by_email(&f.db, f.tenant.id, "ann@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(ann.disabled);
    // The mapping's membership survives apply releasing its manual side.
    let member = group_members::Entity::find()
        .filter(group_members::Column::GroupId.eq(staff.id))
        .filter(group_members::Column::UserId.eq(ann.id))
        .one(&f.db)
        .await
        .unwrap()
        .expect("mapped membership kept");
    assert_eq!(member.idp_id, Some(idp.id));
    assert!(!member.manual && !member.managed);
}

/// Ann, a manual managed member of Staff, and the Staff group.
async fn staffed(f: &Fixture) -> (users::Model, groups::Model) {
    apply(
        f,
        "tenant: contoso\nusers:\n  - { email: ann@example.com, display_name: Ann }\n\
         groups:\n  - { display_name: Staff, members: [ann@example.com] }\n",
    )
    .await
    .unwrap();
    let ann = directory::find_user_by_email(&f.db, f.tenant.id, "ann@example.com")
        .await
        .unwrap()
        .unwrap();
    let staff = groups::Entity::find()
        .filter(groups::Column::TenantId.eq(f.tenant.id))
        .filter(groups::Column::DisplayName.eq("Staff"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    (ann, staff)
}

const DROP_ANN: &str = "tenant: contoso\nusers:\n  - { email: ann@example.com, display_name: Ann }\n\
     groups:\n  - { display_name: Staff, members: [] }\n";

/// Runs the apply dropping Ann from Staff while `writer` holds her
/// membership row, and commits `writer` once apply waits on it.
async fn apply_against(f: &Fixture, writer: DatabaseTransaction) -> Report {
    let commit = async {
        wait_for_lock_waiter(&f.db).await;
        writer.commit().await.unwrap();
    };
    let (report, ()) = tokio::join!(apply(f, DROP_ANN), commit);
    report.unwrap()
}

async fn member_removals(f: &Fixture) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .filter(audit_events::Column::EventType.eq("group.member_remove"))
        .count(&f.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn release_keeps_a_membership_a_mapping_took_over_after_apply_read_it() {
    let f = Fixture::new().await;
    let (ann, staff) = staffed(&f).await;

    // A sign-in through a provider created after apply locked the tenant's
    // IdPs (the management API doesn't take apply's lock) maps Ann into
    // Staff; it holds her row until apply has read it as manual-only.
    let sign_in = f.db.begin().await.unwrap();
    let late = identity_providers::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(f.tenant.id),
        name: Set("Late".into()),
        issuer: Set("https://login.late.example".into()),
        client_id: Set("oauth-late".into()),
        ..Default::default()
    };
    let late = late.insert(&sign_in).await.unwrap();
    sign_in
        .execute_raw(Statement::from_sql_and_values(
            sign_in.get_database_backend(),
            "UPDATE group_members SET idp_id = $1 WHERE group_id = $2 AND user_id = $3",
            [late.id.into(), staff.id.into(), ann.id.into()],
        ))
        .await
        .unwrap();

    let report = apply_against(&f, sign_in).await;
    assert!(
        report
            .changes
            .iter()
            .any(|c| c == "- member ann@example.com of Staff"),
        "{report:#?}"
    );
    let member = group_members::Entity::find()
        .filter(group_members::Column::GroupId.eq(staff.id))
        .filter(group_members::Column::UserId.eq(ann.id))
        .one(&f.db)
        .await
        .unwrap()
        .expect("mapped membership kept");
    assert_eq!(member.idp_id, Some(late.id));
    assert!(!member.manual && !member.managed);
}

#[tokio::test]
async fn release_neither_reports_nor_audits_a_membership_removed_meanwhile() {
    let f = Fixture::new().await;
    let (ann, staff) = staffed(&f).await;
    let removals = member_removals(&f).await;

    // An admin removes Ann from Staff through the management API.
    let admin = f.db.begin().await.unwrap();
    group_members::Entity::delete_many()
        .filter(group_members::Column::GroupId.eq(staff.id))
        .filter(group_members::Column::UserId.eq(ann.id))
        .exec(&admin)
        .await
        .unwrap();

    let report = apply_against(&f, admin).await;
    assert!(
        !report.changes.iter().any(|c| c.starts_with("- member")),
        "{report:#?}"
    );
    assert_eq!(member_removals(&f).await, removals);
}

async fn member_adds(f: &Fixture) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .filter(audit_events::Column::EventType.eq("group.member_add"))
        .count(&f.db)
        .await
        .unwrap()
}

const KEEP_ANN: &str = "tenant: contoso\nusers:\n  - { email: ann@example.com, display_name: Ann }\n\
     groups:\n  - { display_name: Staff, members: [ann@example.com] }\n";

/// Runs the apply keeping Ann in Staff while an admin's uncommitted
/// transaction has deleted her membership, then asserts apply added it back.
async fn apply_keeping_ann_against_removal(f: &Fixture, ann: &users::Model, staff: &groups::Model) {
    let adds = member_adds(f).await;
    let admin = f.db.begin().await.unwrap();
    group_members::Entity::delete_many()
        .filter(group_members::Column::GroupId.eq(staff.id))
        .filter(group_members::Column::UserId.eq(ann.id))
        .exec(&admin)
        .await
        .unwrap();
    let commit = async {
        wait_for_lock_waiter(&f.db).await;
        admin.commit().await.unwrap();
    };
    let (report, ()) = tokio::join!(apply(f, KEEP_ANN), commit);
    let report = report.unwrap();
    assert!(
        report
            .changes
            .iter()
            .any(|c| c == "+ member ann@example.com of Staff"),
        "{report:#?}"
    );
    let member = group_members::Entity::find()
        .filter(group_members::Column::GroupId.eq(staff.id))
        .filter(group_members::Column::UserId.eq(ann.id))
        .one(&f.db)
        .await
        .unwrap()
        .expect("declared membership present");
    assert!(member.manual && member.managed);
    assert_eq!(member_adds(f).await, adds + 1);
}

#[tokio::test]
async fn adopt_adds_a_manual_membership_removed_after_apply_read_it() {
    let f = Fixture::new().await;
    let (ann, staff) = staffed(&f).await;
    // Ann is a manual member apply doesn't manage yet.
    group_members::Entity::update_many()
        .col_expr(group_members::Column::Managed, false.into())
        .filter(group_members::Column::GroupId.eq(staff.id))
        .exec(&f.db)
        .await
        .unwrap();
    apply_keeping_ann_against_removal(&f, &ann, &staff).await;
}

#[tokio::test]
async fn an_up_to_date_member_removed_after_apply_read_it_is_added_back() {
    let f = Fixture::new().await;
    let (ann, staff) = staffed(&f).await;
    apply_keeping_ann_against_removal(&f, &ann, &staff).await;
}

#[tokio::test]
async fn apply_stops_on_a_declared_idp_created_after_it_locked_the_tenants_idps() {
    let f = Fixture::new().await;
    let (ann, _) = staffed(&f).await;

    // An admin holds Ann's row and creates the provider the file declares;
    // apply locks the (still invisible) IdPs, then waits on Ann.
    let admin = f.db.begin().await.unwrap();
    users::Entity::find_by_id(ann.id)
        .lock_exclusive()
        .one(&admin)
        .await
        .unwrap();
    identity_providers::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(f.tenant.id),
        name: Set("Upstream".into()),
        issuer: Set("https://login.upstream.example".into()),
        client_id: Set("oauth-upstream".into()),
        ..Default::default()
    }
    .insert(&admin)
    .await
    .unwrap();
    let rename = format!(
        "tenant: contoso\nusers:\n  - {{ email: ann@example.com, display_name: Ann B }}\n\
         groups:\n  - {{ display_name: Staff, members: [ann@example.com] }}\n{IDP}"
    );
    let commit = async {
        wait_for_lock_waiter(&f.db).await;
        admin.commit().await.unwrap();
    };
    let (report, ()) = tokio::join!(apply(&f, &rename), commit);
    let err = format!("{:#}", report.unwrap_err());
    assert!(err.contains("created while apply ran"), "{err}");
    let ann = users::Entity::find_by_id(ann.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ann.display_name, "Ann");
}
