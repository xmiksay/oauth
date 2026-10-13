// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Users, groups, members and directory roles through the management API.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{call, mint_user_token, user_with_roles},
};
use entity::{
    audit_events,
    enums::DirectoryRole::{GlobalAdmin, UserAdmin},
};
use sea_orm::{ConnectionTrait, EntityTrait};
use serde_json::json;

const USERS: &str = "/api/v1/tenants/contoso/users";
const ROLES: &str = "/api/v1/tenants/contoso/directory-roles";
const GROUPS: &str = "/api/v1/tenants/contoso/groups";
const AUDIT: &str = "/api/v1/tenants/contoso/audit-events";

#[tokio::test]
async fn last_global_admin_cannot_be_removed() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let (_, roles) = call(
        &f.app,
        Method::GET,
        &format!("{ROLES}?user_id={}", ga.id),
        Some(&token),
        None,
    )
    .await;
    let assignment = roles["items"][0]["id"].as_str().unwrap().to_owned();
    let me = format!("{USERS}/{}", ga.id);

    let (st, _) = call(
        &f.app,
        Method::DELETE,
        &format!("{ROLES}/{assignment}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &me,
        Some(&token),
        Some(&json!({ "disabled": true })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = call(&f.app, Method::DELETE, &me, Some(&token), None).await;
    assert_eq!(st, StatusCode::CONFLICT);

    // A disabled second admin doesn't count; an enabled one does.
    let second = user_with_roles(&f.db, f.tenant.id, "ga2@example.com", &[GlobalAdmin]).await;
    f.db.execute_unprepared(&format!(
        "UPDATE users SET disabled = true WHERE id = '{}'",
        second.id
    ))
    .await
    .unwrap();
    let (st, _) = call(
        &f.app,
        Method::DELETE,
        &format!("{ROLES}/{assignment}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let path = format!("{USERS}/{}", second.id);
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(&json!({ "disabled": false })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = call(
        &f.app,
        Method::DELETE,
        &format!("{ROLES}/{assignment}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let bad_role = json!({ "user_id": ga.id, "role": "Root" });
    let second_token = mint_user_token(&f.db, &f.config, &f.tenant, &second).await;
    let (st, _) = call(
        &f.app,
        Method::POST,
        ROLES,
        Some(&second_token),
        Some(&bad_role),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn users_and_groups_crud() {
    let f = Fixture::new().await;
    let ua = user_with_roles(&f.db, f.tenant.id, "ua@example.com", &[UserAdmin]).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ua).await;
    let tok = Some(token.as_str());

    let (st, created) = call(
        &f.app,
        Method::POST,
        USERS,
        tok,
        Some(&json!({ "email": "Bob@Example.com", "display_name": "Bob" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let otp = created["one_time_password"].as_str().unwrap();
    assert_eq!(otp.len(), 24);
    assert_eq!(created["user"]["must_change_password"], true);
    let bob = created["user"]["id"].as_str().unwrap().to_owned();
    let (st, _) = call(
        &f.app,
        Method::POST,
        USERS,
        tok,
        Some(&json!({ "email": "bob@example.com", "display_name": "Bob 2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = call(
        &f.app,
        Method::POST,
        USERS,
        tok,
        Some(&json!({ "email": "x@example.com", "display_name": "X", "password": "short" })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (_, found) = call(
        &f.app,
        Method::GET,
        &format!("{USERS}?search=BOB"),
        tok,
        None,
    )
    .await;
    assert_eq!(found["items"].as_array().unwrap().len(), 1);
    let (_, none) = call(
        &f.app,
        Method::GET,
        &format!("{USERS}?search=%25"),
        tok,
        None,
    )
    .await;
    assert_eq!(
        none["items"].as_array().unwrap().len(),
        0,
        "LIKE wildcards are literal"
    );
    let bob_path = format!("{USERS}/{bob}");
    let (st, detail) = call(&f.app, Method::GET, &bob_path, tok, None).await;
    assert_eq!(
        (st, detail["mfa"]["totp"].as_bool()),
        (StatusCode::OK, Some(false))
    );
    assert_eq!(
        call(
            &f.app,
            Method::GET,
            &format!("{USERS}/not-a-uuid"),
            tok,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let (st, reset) = call(
        &f.app,
        Method::POST,
        &format!("{bob_path}/reset-password"),
        tok,
        Some(&json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_ne!(reset["one_time_password"].as_str().unwrap(), otp);
    let (st, _) = call(
        &f.app,
        Method::POST,
        &format!("{bob_path}/reset-mfa"),
        tok,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, sessions) = call(
        &f.app,
        Method::GET,
        &format!("{bob_path}/sessions"),
        tok,
        None,
    )
    .await;
    assert_eq!(
        (st, sessions["items"].as_array().map(Vec::len)),
        (StatusCode::OK, Some(0))
    );
    let (st, upd) = call(
        &f.app,
        Method::PATCH,
        &bob_path,
        tok,
        Some(&json!({ "display_name": "Robert", "email": "ann@example.com" })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{upd}");

    // Groups and members.
    let (st, group) = call(
        &f.app,
        Method::POST,
        GROUPS,
        tok,
        Some(&json!({ "display_name": "Ops", "description": "On call" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{group}");
    let members = format!("{GROUPS}/{}/members", group["id"].as_str().unwrap());
    let add = json!({ "user_id": bob });
    assert_eq!(
        call(&f.app, Method::POST, &members, tok, Some(&add))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, Method::POST, &members, tok, Some(&add))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let ghost = json!({ "user_id": uuid::Uuid::now_v7() });
    assert_eq!(
        call(&f.app, Method::POST, &members, tok, Some(&ghost))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (_, listed) = call(&f.app, Method::GET, &members, tok, None).await;
    assert_eq!(listed["items"][0]["email"], "Bob@Example.com");
    let one = format!("{members}/{bob}");
    assert_eq!(
        call(&f.app, Method::DELETE, &one, tok, None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &one, tok, None).await.0,
        StatusCode::NOT_FOUND
    );
    let group_path = format!("{GROUPS}/{}", group["id"].as_str().unwrap());
    let (st, renamed) = call(
        &f.app,
        Method::PATCH,
        &group_path,
        tok,
        Some(&json!({ "display_name": "SRE" })),
    )
    .await;
    assert_eq!(
        (st, renamed["display_name"].as_str()),
        (StatusCode::OK, Some("SRE"))
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &group_path, tok, None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, Method::DELETE, &bob_path, tok, None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, Method::GET, &bob_path, tok, None).await.0,
        StatusCode::NOT_FOUND
    );

    // Audit log: newest first, filterable, with the acting user.
    let (_, log) = call(
        &f.app,
        Method::GET,
        &format!("{AUDIT}?actor_id={}&limit=3", ua.id),
        tok,
        None,
    )
    .await;
    let items = log["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["event_type"], "user.delete");
    assert_eq!(items[0]["actor_type"], "user");
    assert!(log["next_cursor"].is_string());
    let (_, creates) = call(
        &f.app,
        Method::GET,
        &format!("{AUDIT}?event_type=user.create&target_id={bob}"),
        tok,
        None,
    )
    .await;
    assert_eq!(creates["items"].as_array().unwrap().len(), 1);
    let (st, _) = call(
        &f.app,
        Method::GET,
        &format!("{AUDIT}?from=yesterday"),
        tok,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let log = serde_json::to_string(
        &audit_events::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .iter()
            .map(|e| &e.details)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!log.contains(otp) && !log.contains(reset["one_time_password"].as_str().unwrap()));
}
