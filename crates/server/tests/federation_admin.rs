//! `/api/v1/identity-providers`: CRUD, authorization (GlobalAdmin writes,
//! any directory role reads, apps nothing), secret redaction, validation,
//! tenant isolation and the lockout count.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::{Method, StatusCode};
use common::{
    ORIGIN, at,
    federation::{Fed, IDPS},
    mgmt::{audited, call, mint_app_token, mint_user_token, user_with_roles},
    upstream::CLIENT_SECRET,
};
use entity::{
    enums::DirectoryRole::{GlobalAdmin, UserAdmin},
    identity_providers,
};
use oauth_server::directory::{self, NewTenant, builtin_apps::ROLE_READ_WRITE_ALL};
use sea_orm::EntityTrait;
use serde_json::{Value, json};
use uuid::Uuid;

fn has_no_secret(body: &Value) {
    let text = body.to_string();
    assert!(!text.contains(CLIENT_SECRET), "{text}");
    assert!(body.get("client_secret").is_none() && body.get("client_secret_sealed").is_none());
}

#[tokio::test]
async fn global_admins_manage_providers_and_secrets_stay_write_only() {
    let fed = Fed::new().await;
    let (status, created) = fed.api(Method::POST, IDPS, Some(fed.body(json!({})))).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    has_no_secret(&created);
    assert_eq!(created["has_secret"], true);
    assert_eq!(
        created["redirect_uri"],
        format!("{ORIGIN}/federation/callback")
    );
    assert_eq!(created["policy"], "jit");
    assert_eq!(created["scopes"], json!(["openid", "email", "profile"]));
    assert_eq!(created["users_only_via"], 0);
    let id = created["id"].as_str().unwrap();
    let row = identity_providers::Entity::find_by_id(Uuid::parse_str(id).unwrap())
        .one(&fed.f.db)
        .await
        .unwrap()
        .unwrap();
    let sealed = row.client_secret_sealed.unwrap();
    assert!(
        !sealed
            .windows(CLIENT_SECRET.len())
            .any(|w| w == CLIENT_SECRET.as_bytes())
    );
    let (status, list) = fed.api(Method::GET, IDPS, None).await;
    assert_eq!(status, StatusCode::OK);
    has_no_secret(&list);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    // Echoing unchanged values is not an update.
    let path = format!("{IDPS}/{id}");
    let same = json!({ "name": "Upstream", "policy": "jit", "enabled": true });
    fed.patch_idp(id, same).await;
    let target = Uuid::parse_str(id).unwrap();
    assert!(
        audited(&fed.f.db, "identity_provider.update", target)
            .await
            .is_empty()
    );
    let changed = fed
        .patch_idp(
            id,
            json!({ "client_secret": null, "visible": false, "email_domains": ["Up.Example"] }),
        )
        .await;
    assert_eq!(changed["has_secret"], false);
    assert_eq!(changed["email_domains"], json!(["up.example"]));
    let updates = audited(&fed.f.db, "identity_provider.update", target).await;
    assert_eq!(
        updates[0]["fields"],
        json!(["client_secret", "email_domains", "visible"])
    );
    has_no_secret(&json!(updates));
    let changed = fed
        .patch_idp(id, json!({ "client_secret": "new-one" }))
        .await;
    assert_eq!(changed["has_secret"], true);
    let (status, _) = fed.api(Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = fed.api(Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        audited(&fed.f.db, "identity_provider.delete", target)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn only_global_admins_write_and_apps_see_nothing() {
    let fed = Fed::new().await;
    let id = fed.idp(json!({})).await;
    let path = format!("{IDPS}/{id}");
    let ua = user_with_roles(&fed.f.db, fed.f.tenant.id, "ua@example.com", &[UserAdmin]).await;
    let ua = mint_user_token(&fed.f.db, &fed.f.config, &fed.f.tenant, &ua).await;
    let member = mint_user_token(&fed.f.db, &fed.f.config, &fed.f.tenant, &fed.f.user).await;
    let app = mint_app_token(
        &fed.f.db,
        &fed.f.config,
        &fed.f.tenant,
        Some(ROLE_READ_WRITE_ALL),
    )
    .await;
    let app_ = &fed.f.app;
    let (status, body) = call(app_, Method::GET, &path, Some(&ua), None).await;
    assert_eq!(status, StatusCode::OK);
    has_no_secret(&body);
    let writes = [
        (
            Method::POST,
            IDPS.to_owned(),
            Some(fed.body(json!({ "name": "X" }))),
        ),
        (
            Method::PATCH,
            path.clone(),
            Some(json!({ "enabled": false })),
        ),
        (Method::DELETE, path.clone(), None),
    ];
    for (method, uri, body) in writes {
        let (status, _) = call(app_, method.clone(), &uri, Some(&ua), body.as_ref()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "UserAdmin {method} {uri}");
        let (status, _) = call(app_, method.clone(), &uri, Some(&app), body.as_ref()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "app {method} {uri}");
    }
    for token in [&member, &app] {
        let (status, _) = call(app_, Method::GET, IDPS, Some(token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn input_is_validated() {
    let fed = Fed::new().await;
    fed.idp(json!({ "email_domains": ["taken.example"] })).await;
    let bad = [
        json!({ "issuer": "http://idp.example" }),
        json!({ "issuer": "https://idp.example/?q=1" }),
        json!({ "discovery_url": "ftp://idp.example/x" }),
        json!({ "scopes": ["email"] }),
        json!({ "policy": "auto" }),
        json!({ "client_auth": "private_key_jwt" }),
        json!({ "email_domains": ["not a domain"] }),
        json!({ "name": "" }),
        json!({ "surprise": true }),
    ];
    for extra in bad {
        let mut body = fed.body(extra.clone());
        body["name"] = extra.get("name").cloned().unwrap_or(json!("Another"));
        let (status, out) = fed.api(Method::POST, IDPS, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{extra}: {out}");
    }
    let (status, _) = fed.api(Method::POST, IDPS, Some(fed.body(json!({})))).await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate name");
    let dup_domain = fed.body(json!({ "name": "Two", "email_domains": ["TAKEN.example"] }));
    let (status, _) = fed.api(Method::POST, IDPS, Some(dup_domain)).await;
    assert_eq!(status, StatusCode::CONFLICT, "domain of another IdP");
    let (status, _) = fed
        .api(Method::POST, IDPS, Some(json!({ "name": "Incomplete" })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn providers_are_tenant_scoped_and_report_lockout() {
    let fed = Fed::new().await;
    let id = fed.idp(json!({})).await;
    let other = directory::create_tenant(
        &fed.f.db,
        &fed.f.config,
        NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let ga = user_with_roles(&fed.f.db, other.id, "ga@fabrikam.example", &[GlobalAdmin]).await;
    let token = mint_user_token(&fed.f.db, &fed.f.config, &other, &ga).await;
    let app = &fed.f.app;
    let theirs = at("fabrikam", &format!("{IDPS}/{id}"));
    let (status, _) = call(app, Method::GET, &theirs, Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(app, Method::DELETE, &theirs, Some(&token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, list) = call(app, Method::GET, &at("fabrikam", IDPS), Some(&token), None).await;
    assert_eq!(list["items"], json!([]));
    // A JIT user can sign in only through this provider.
    fed.sign_in(&mut fed.f.browser(), &id).await;
    let (_, detail) = fed.api(Method::GET, &format!("{IDPS}/{id}"), None).await;
    assert_eq!(detail["users_only_via"], 1);
    // The fixture user has a password: linking them adds no lockout.
    let (status, _) = fed.api(Method::DELETE, &format!("{IDPS}/{id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let events = common::mgmt::audited_any(&fed.f.db, "identity_provider.delete").await;
    assert_eq!(events[0]["users_only_via"], 1);
}
