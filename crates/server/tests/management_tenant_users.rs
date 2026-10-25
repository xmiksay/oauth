// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A system Global Admin looking up another tenant's users and resetting
//! their password / MFA (`/api/v1/tenants/{slug}/users` on the system host).
mod common;

use axum::http::{Method, StatusCode};
use common::{
    authenticator::{Alg, Authenticator},
    flow::{Fixture, PASSWORD, T},
    mgmt::{call, mint_app_token, mint_user_token, user_with_roles},
    passkeys::{drop_password, register_ok},
};
use entity::{
    audit_events,
    enums::{
        ActorType,
        DirectoryRole::{GlobalAdmin, UserAdmin},
    },
    tenants, user_totp, users, webauthn_credentials,
};
use oauth_server::{
    bootstrap,
    directory::{self, builtin_apps, password},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::{Value, json};
use uuid::Uuid;

fn sys(path: &str) -> String {
    common::at("system", path)
}

fn users_of(slug: &str, rest: &str) -> String {
    sys(&format!("/api/v1/tenants/{slug}/users{rest}"))
}

/// The fixture plus a bootstrapped system tenant, its root Global Admin and
/// a management token of theirs.
async fn setup() -> (Fixture, tenants::Model, users::Model, String) {
    let f = Fixture::new().await;
    let opts = bootstrap::Options {
        admin_email: "root@example.com".into(),
        display_name: None,
        reset_password: false,
    };
    bootstrap::run(&f.db, &f.config, &opts).await.unwrap();
    let system = directory::find_system_tenant(&f.db).await.unwrap().unwrap();
    let root = directory::find_user_by_email(&f.db, system.id, "root@example.com")
        .await
        .unwrap()
        .unwrap();
    let token = mint_user_token(&f.db, &f.config, &system, &root).await;
    (f, system, root, token)
}

/// `event_type` audit rows about `user` in `tenant_id`, oldest first.
async fn events(
    f: &Fixture,
    tenant_id: Uuid,
    event_type: &str,
    user: Uuid,
) -> Vec<audit_events::Model> {
    audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(tenant_id))
        .filter(audit_events::Column::EventType.eq(event_type))
        .filter(audit_events::Column::TargetId.eq(user))
        .order_by_asc(audit_events::Column::Id)
        .all(&f.db)
        .await
        .unwrap()
}

/// Exactly one event in each log: the system admin's own (actor: them) and
/// the target tenant's (actor: them too, `via: system_admin`); returns the target tenant's details.
async fn audited_in_both(
    f: &Fixture,
    system: &tenants::Model,
    root: &users::Model,
    event_type: &str,
    user: Uuid,
) -> Value {
    let own = events(f, system.id, event_type, user).await;
    assert_eq!(own.len(), 1, "{own:?}");
    assert_eq!(own[0].actor_type, ActorType::User);
    assert_eq!(own[0].actor_id, Some(root.id));
    assert_eq!(own[0].details["tenant_slug"], T);
    assert_eq!(own[0].details["tenant_id"], json!(f.tenant.id));
    assert!(own[0].details.get("via").is_none());
    let theirs = events(f, f.tenant.id, event_type, user).await;
    assert_eq!(theirs.len(), 1, "{theirs:?}");
    assert_eq!(theirs[0].actor_type, ActorType::User);
    assert_eq!(theirs[0].actor_id, Some(root.id));
    assert_eq!(theirs[0].details["via"], "system_admin");
    assert!(theirs[0].details.get("system_admin_id").is_none());
    assert_eq!(theirs[0].details["tenant_slug"], T);
    theirs[0].details.clone()
}

#[tokio::test]
async fn system_admin_finds_and_resets_a_sub_tenant_admins_password() {
    let (f, system, root, token) = setup().await;
    let tok = Some(token.as_str());
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga_token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;

    let (st, page) = call(&f.app, Method::GET, &users_of(T, "?limit=1"), tok, None).await;
    assert_eq!(st, StatusCode::OK, "{page}");
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let cursor = page["next_cursor"].as_str().unwrap();
    let rest = users_of(T, &format!("?limit=1&cursor={cursor}"));
    let (_, page) = call(&f.app, Method::GET, &rest, tok, None).await;
    assert_eq!(page["items"][0]["email"], "ga@example.com");
    let (st, found) = call(&f.app, Method::GET, &users_of(T, "?search=GA@"), tok, None).await;
    assert_eq!(st, StatusCode::OK);
    let items = found["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{found}");
    assert_eq!(items[0]["id"], json!(ga.id));
    assert_eq!(items[0]["has_password"], true);

    let one = users_of(T, &format!("/{}", ga.id));
    let (st, detail) = call(&f.app, Method::GET, &one, tok, None).await;
    assert_eq!(st, StatusCode::OK, "{detail}");
    assert_eq!(detail["email"], "ga@example.com");
    assert_eq!(detail["directory_roles"], json!(["GlobalAdmin"]));
    assert_eq!(detail["mfa"]["totp"], false);
    assert!(detail["identities"].is_array());

    // Only a generated password: any field is refused, nothing changes.
    let reset = users_of(T, &format!("/{}/reset-password", ga.id));
    for body in [
        json!({ "password": "an admin chosen passphrase" }),
        json!({ "must_change_password": false }),
    ] {
        let (st, _) = call(&f.app, Method::POST, &reset, tok, Some(&body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    }
    assert!(
        events(&f, f.tenant.id, "user.password_reset", ga.id)
            .await
            .is_empty()
    );

    let (st, _) = call(&f.app, Method::GET, "/api/v1/users", Some(&ga_token), None).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "the admin's session is live before the reset"
    );
    let (st, out) = call(&f.app, Method::POST, &reset, tok, Some(&json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{out}");
    assert_eq!(out["must_change_password"], true);
    let otp = out["one_time_password"].as_str().unwrap();
    let after = directory::find_user_by_email(&f.db, f.tenant.id, "ga@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(after.must_change_password);
    let hash = after.password_hash.as_deref().unwrap();
    assert!(password::verify(otp, hash).await.unwrap());
    assert!(!password::verify(PASSWORD, hash).await.unwrap());
    // Signed out everywhere: the old session's management token is dead.
    let (st, _) = call(&f.app, Method::GET, "/api/v1/users", Some(&ga_token), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let details = audited_in_both(&f, &system, &root, "user.password_reset", ga.id).await;
    assert_eq!(details["generated"], true);
    assert_eq!(details["must_change_password"], true);
    for e in audit_events::Entity::find().all(&f.db).await.unwrap() {
        assert!(!e.details.to_string().contains(otp));
    }
}

#[tokio::test]
async fn system_admin_resets_mfa_but_never_locks_a_passkey_only_user_out() {
    let (f, system, root, token) = setup().await;
    let tok = Some(token.as_str());
    f.enroll_totp(&f.user).await;
    let reset = users_of(T, &format!("/{}/reset-mfa", f.user.id));
    let (st, body) = call(&f.app, Method::POST, &reset, tok, None).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{body}");
    let totp = user_totp::Entity::find_by_id(f.user.id)
        .one(&f.db)
        .await
        .unwrap();
    assert!(totp.is_none());
    let details = audited_in_both(&f, &system, &root, "user.mfa_reset", f.user.id).await;
    assert_eq!(details["passkeys_removed"], 0);
    assert_eq!(details["telegram_unlinked"], false);

    // A passkey and no password: removing it would lock the user out.
    let ann_token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::new(Alg::Es256, T);
    register_ok(&f, &ann_token, &mut auth).await;
    drop_password(&f, &f.user).await;
    let (st, body) = call(&f.app, Method::POST, &reset, tok, None).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    let left = webauthn_credentials::Entity::find()
        .all(&f.db)
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    // Refused: still one event per log.
    audited_in_both(&f, &system, &root, "user.mfa_reset", f.user.id).await;

    // The documented recovery: reset the password, then the MFA.
    let pw = users_of(T, &format!("/{}/reset-password", f.user.id));
    let (st, _) = call(&f.app, Method::POST, &pw, tok, Some(&json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = call(&f.app, Method::POST, &reset, tok, None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let left = webauthn_credentials::Entity::find()
        .all(&f.db)
        .await
        .unwrap();
    assert!(left.is_empty());
}

#[tokio::test]
async fn tenant_user_routes_refuse_wrong_tenants_users_and_callers() {
    let (f, system, root, token) = setup().await;
    let tok = Some(token.as_str());
    let ann = f.user.id;
    let routes = |slug: &str, id: Uuid| {
        [
            (Method::GET, users_of(slug, "")),
            (Method::GET, users_of(slug, &format!("/{id}"))),
            (
                Method::POST,
                users_of(slug, &format!("/{id}/reset-password")),
            ),
            (Method::POST, users_of(slug, &format!("/{id}/reset-mfa"))),
        ]
    };
    let empty = json!({});
    // The system tenant is managed through its own Users page.
    for (method, path) in routes("system", root.id) {
        let (st, _) = call(&f.app, method, &path, tok, Some(&empty)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{path}");
    }
    for (method, path) in routes("nope", ann) {
        let (st, _) = call(&f.app, method, &path, tok, Some(&empty)).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{path}");
    }

    // A disabled tenant's users can still be helped.
    let new = json!({ "slug": "fabrikam", "display_name": "Fabrikam", "admin_email": "boss@fabrikam.example" });
    let (st, _) = call(
        &f.app,
        Method::POST,
        &sys("/api/v1/tenants"),
        tok,
        Some(&new),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let off = json!({ "disabled": true });
    let path = sys("/api/v1/tenants/fabrikam");
    let (st, _) = call(&f.app, Method::PATCH, &path, tok, Some(&off)).await;
    assert_eq!(st, StatusCode::OK);
    let fabrikam = directory::find_tenant_by_slug(&f.db, "fabrikam")
        .await
        .unwrap()
        .unwrap();
    let boss = directory::find_user_by_email(&f.db, fabrikam.id, "boss@fabrikam.example")
        .await
        .unwrap()
        .unwrap();
    let (st, list) = call(&f.app, Method::GET, &users_of("fabrikam", ""), tok, None).await;
    assert_eq!(
        (st, list["items"][0]["id"].clone()),
        (StatusCode::OK, json!(boss.id))
    );
    let reset = users_of("fabrikam", &format!("/{}/reset-password", boss.id));
    let (st, out) = call(&f.app, Method::POST, &reset, tok, Some(&empty)).await;
    assert_eq!(st, StatusCode::OK, "{out}");
    assert!(out["one_time_password"].is_string());

    // Users of another tenant (fabrikam's, the system's) are 404 under contoso.
    for id in [boss.id, root.id] {
        for (method, path) in routes(T, id).into_iter().skip(1) {
            let (st, _) = call(&f.app, method, &path, tok, Some(&empty)).await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{path}");
        }
    }

    // Callers that aren't a system Global Admin on the system host.
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga_token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let member = user_with_roles(&f.db, system.id, "member@example.com", &[UserAdmin]).await;
    let member_token = mint_user_token(&f.db, &f.config, &system, &member).await;
    let app_token = mint_app_token(
        &f.db,
        &f.config,
        &system,
        Some(builtin_apps::ROLE_READ_WRITE_ALL),
    )
    .await;
    for (method, path) in routes(T, ann) {
        let cases = [
            (None, StatusCode::UNAUTHORIZED),
            (Some(ga_token.as_str()), StatusCode::UNAUTHORIZED),
            (Some(member_token.as_str()), StatusCode::FORBIDDEN),
            (Some(app_token.as_str()), StatusCode::FORBIDDEN),
        ];
        for (who, expected) in cases {
            let (st, _) = call(&f.app, method.clone(), &path, who, Some(&empty)).await;
            assert_eq!(st, expected, "{path}");
        }
        // On a tenant host the resource doesn't exist, whoever asks.
        let local = path.replace("system.", &format!("{T}."));
        for who in [&ga_token, &token] {
            let (st, _) = call(&f.app, method.clone(), &local, Some(who), Some(&empty)).await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{local}");
        }
    }
    assert!(
        events(&f, f.tenant.id, "user.password_reset", ann)
            .await
            .is_empty()
    );
    assert!(
        events(&f, f.tenant.id, "user.mfa_reset", ann)
            .await
            .is_empty()
    );
}
