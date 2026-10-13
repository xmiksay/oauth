// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Sign-in audit events, audit log paging and the retention sweep.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    browser::authorize_url,
    flow::{Fixture, WEB_CB},
    mgmt::{call, mint_user_token, post, user_with_roles},
};
use entity::audit_events;
use entity::enums::DirectoryRole::GlobalAdmin;
use oauth_server::jobs::sweeper;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::{Value, json};

#[tokio::test]
async fn sign_ins_are_audited_and_old_events_swept() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let tx = browser
        .authorize(&authorize_url("web-app", WEB_CB, "openid", &[]))
        .await
        .unwrap();
    let wrong = json!({ "email": "ann@example.com", "password": "wrong password!" });
    assert_eq!(
        browser.step(&tx, "password", wrong).await.0,
        StatusCode::UNAUTHORIZED
    );
    let ghost = json!({ "email": "ghost@example.com", "password": "wrong password!" });
    assert_eq!(
        browser.step(&tx, "password", ghost).await.0,
        StatusCode::UNAUTHORIZED
    );
    browser.complete_login(&tx, "ann@example.com").await;

    let events = audit_events::Entity::find()
        .filter(audit_events::Column::EventType.eq("sign_in"))
        .all(&f.db)
        .await
        .unwrap();
    let outcomes: Vec<(Option<uuid::Uuid>, String, Value)> = events
        .iter()
        .map(|e| {
            (
                e.actor_id,
                format!("{:?}", e.outcome),
                e.details["reason"].clone(),
            )
        })
        .collect();
    assert!(
        outcomes.contains(&(Some(f.user.id), "Failure".into(), json!("invalid_password"))),
        "{outcomes:?}"
    );
    assert!(
        outcomes.contains(&(None, "Failure".into(), json!("unknown_account"))),
        "{outcomes:?}"
    );
    assert!(
        outcomes.contains(&(Some(f.user.id), "Success".into(), Value::Null)),
        "{outcomes:?}"
    );
    let text =
        serde_json::to_string(&events.iter().map(|e| &e.details).collect::<Vec<_>>()).unwrap();
    assert!(
        !text.contains("wrong password!") && !text.contains("ghost@"),
        "{text}"
    );

    // Retention: rows older than the tenant's audit_retention_days go.
    let total = audit_events::Entity::find().count(&f.db).await.unwrap();
    f.db.execute_unprepared(
        "UPDATE tenants SET audit_retention_days = 30; \
         UPDATE audit_events SET at = now() - interval '31 days' \
         WHERE id = (SELECT id FROM audit_events ORDER BY id LIMIT 1)",
    )
    .await
    .unwrap();
    let report = sweeper::run_once(&f.db).await.unwrap().unwrap();
    assert!(report.contains(&("audit_events", 1)), "{report:?}");
    assert_eq!(
        audit_events::Entity::find().count(&f.db).await.unwrap(),
        total - 1
    );
}

#[tokio::test]
async fn audit_log_pages_newest_first_without_overlap() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    for n in 0..7 {
        let body = json!({ "display_name": format!("Group {n}") });
        let (st, _) = post(&f, &token, "/api/v1/tenants/contoso/groups", body).await;
        assert_eq!(st, StatusCode::CREATED);
    }
    let total = audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .count(&f.db)
        .await
        .unwrap();
    assert!(total >= 7);

    let mut seen: Vec<uuid::Uuid> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut path = "/api/v1/tenants/contoso/audit-events?limit=3".to_owned();
        if let Some(c) = &cursor {
            path.push_str(&format!("&cursor={c}"));
        }
        let (st, page) = call(&f.app, Method::GET, &path, Some(&token), None).await;
        assert_eq!(st, StatusCode::OK, "{page}");
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 3);
        seen.extend(
            items
                .iter()
                .map(|e| e["id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap()),
        );
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    assert_eq!(
        u64::try_from(seen.len()).unwrap(),
        total,
        "every event exactly once"
    );
    assert!(
        seen.windows(2).all(|w| w[0] > w[1]),
        "strictly decreasing ids: {seen:?}"
    );
}
