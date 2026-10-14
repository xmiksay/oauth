// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Passkeys in the admin center, the reset-MFA lockout rule and the
//! store's own guards.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    authenticator::{Alg, Authenticator},
    flow::{Fixture, T},
    mgmt::{audited, call, mint_user_token, user_with_roles},
    passkeys::{drop_password, register_ok},
};
use entity::{enums::DirectoryRole, webauthn_credentials};
use sea_orm::EntityTrait;
use serde_json::json;

#[tokio::test]
async fn admins_list_remove_and_reset_passkeys_without_locking_users_out() {
    let f = Fixture::new().await;
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::UserAdmin],
    )
    .await;
    let admin_token = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let (mut a, mut b) = (
        Authenticator::new(Alg::Es256, T),
        Authenticator::new(Alg::Es256, T),
    );
    register_ok(&f, &token, &mut a).await;
    register_ok(&f, &token, &mut b).await;
    let users = format!("/api/v1/users/{}", f.user.id);
    let tok = Some(admin_token.as_str());
    let (status, list) = call(&f.app, Method::GET, &format!("{users}/passkeys"), tok, None).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<String> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 2);
    let (_, detail) = call(&f.app, Method::GET, &users, tok, None).await;
    assert_eq!(detail["mfa"]["passkeys"], 2);

    // Without a password, the last passkey stays and reset-mfa is refused.
    drop_password(&f, &f.user).await;
    let remove = |id: &str| format!("{users}/passkeys/{id}");
    assert_eq!(
        call(&f.app, Method::DELETE, &remove(&ids[0]), tok, None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (status, body) = call(&f.app, Method::DELETE, &remove(&ids[1]), tok, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = call(
        &f.app,
        Method::POST,
        &format!("{users}/reset-mfa"),
        tok,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        webauthn_credentials::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .len(),
        1
    );

    // The documented recovery: reset the password, then the MFA.
    let reset = json!({ "password": "an admin chosen passphrase" });
    let (status, _) = call(
        &f.app,
        Method::POST,
        &format!("{users}/reset-password"),
        tok,
        Some(&reset),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &f.app,
        Method::POST,
        &format!("{users}/reset-mfa"),
        tok,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        webauthn_credentials::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .is_empty()
    );
    let resets = audited(&f.db, "user.mfa_reset", f.user.id).await;
    assert_eq!(resets, vec![json!({ "passkeys_removed": 1 })]);
    let removals = audited(&f.db, "user.mfa.passkey_remove", f.user.id).await;
    assert_eq!(removals[0]["via"], "admin");

    // Other tenants' passkey ids and other users' are 404.
    let other = format!("/api/v1/users/{}/passkeys/{}", admin.id, ids[1]);
    assert_eq!(
        call(&f.app, Method::DELETE, &other, tok, None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn store_guards_hold_on_their_own() {
    use oauth_server::{passkey::store, webauthn::assert::Asserted};
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::new(Alg::Es256, T);
    register_ok(&f, &token, &mut auth).await;
    let stale = webauthn_credentials::Entity::find()
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    // A concurrent assertion advanced the counter after `stale` was read:
    // the statement re-checks it and refuses the older count.
    let at = |sign_count| Asserted {
        sign_count,
        backup_state: false,
    };
    assert!(store::record_use(&f.db, &stale, at(5)).await.unwrap());
    assert!(!store::record_use(&f.db, &stale, at(3)).await.unwrap());
    assert!(!store::record_use(&f.db, &stale, at(5)).await.unwrap());
    assert!(!store::record_use(&f.db, &stale, at(0)).await.unwrap());
    assert!(store::record_use(&f.db, &stale, at(6)).await.unwrap());
    // Credential ids are looked up within the tenant only.
    let other = oauth_server::directory::create_tenant(
        &f.db,
        &f.config,
        oauth_server::directory::NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let id = &auth.credential_id;
    let here = store::find_by_credential_id(&f.db, f.tenant.id, id).await;
    assert!(here.unwrap().is_some());
    let there = store::find_by_credential_id(&f.db, other.id, id).await;
    assert!(there.unwrap().is_none());
}
