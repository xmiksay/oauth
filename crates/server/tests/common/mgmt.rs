//! Management API helpers: minting management-API tokens directly (the
//! login flow itself is covered elsewhere) and calling `/api/v1`.

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use entity::{
    applications,
    enums::{ClientType, DirectoryRole},
    tenants, users,
};
use oauth_server::{
    authn::session::{self, NewSession},
    config::Config,
    directory::{self, builtin_apps},
    oidc::client_auth,
    tokens::{self, Delegated},
};
use sea_orm::DatabaseConnection;
use serde_json::Value;
use uuid::Uuid;

use super::{
    browser::send,
    seed::{add_user, insert},
};

pub async fn app_by_client_id(
    db: &DatabaseConnection,
    tenant_id: Uuid,
    client_id: &str,
) -> applications::Model {
    client_auth::find_client(db, tenant_id, client_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no app {client_id}"))
}

/// A delegated management-API access token for `user`, as the admin portal
/// would get it (`scopes` = the management API scopes granted).
pub async fn mint_user_token_with(
    db: &DatabaseConnection,
    config: &Config,
    tenant: &tenants::Model,
    user: &users::Model,
    scopes: &[&str],
) -> String {
    let client = app_by_client_id(db, tenant.id, builtin_apps::ADMIN_PORTAL).await;
    let api = app_by_client_id(db, tenant.id, builtin_apps::MANAGEMENT_API).await;
    let issuer = config.issuer(&tenant.slug);
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    // Management tokens are only honoured while their session lives.
    let (session, _cookie) = session::create(
        db,
        config,
        NewSession {
            tenant_id: tenant.id,
            user_id: user.id,
            amr: &["pwd".to_owned()],
            auth_time: chrono::Utc::now().fixed_offset(),
            ip: None,
            user_agent: None,
        },
    )
    .await
    .unwrap();
    tokens::issue_delegated(
        db,
        &config.master_key,
        Delegated {
            tenant,
            issuer: &issuer,
            client: &client,
            user,
            session_id: session.id,
            amr: &["pwd".to_owned()],
            auth_time: chrono::Utc::now().fixed_offset(),
            nonce: None,
            oidc_scopes: &[],
            resource: Some(&api),
            resource_scopes: &scopes,
            authorization_code_id: None,
            refresh: None,
        },
    )
    .await
    .unwrap()
    .access_token
}

pub async fn mint_user_token(
    db: &DatabaseConnection,
    config: &Config,
    tenant: &tenants::Model,
    user: &users::Model,
) -> String {
    mint_user_token_with(
        db,
        config,
        tenant,
        user,
        &[builtin_apps::SCOPE_ACCESS_AS_USER],
    )
    .await
}

/// A client-credentials management-API token of a new confidential app
/// holding management-API app role `role` (none: no role at all).
pub async fn mint_app_token(
    db: &DatabaseConnection,
    config: &Config,
    tenant: &tenants::Model,
    role: Option<&str>,
) -> String {
    use entity::{app_role_assignments, app_roles};
    use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};

    let api = app_by_client_id(db, tenant.id, builtin_apps::MANAGEMENT_API).await;
    let client_id = format!("svc-{}", Uuid::now_v7());
    let client = super::seed::add_app(
        db,
        tenant.id,
        &client_id,
        ClientType::Confidential,
        None,
        entity::enums::AccessTokenFormat::Jwt,
        entity::enums::SigningAlg::Rs256,
    )
    .await;
    if let Some(role) = role {
        let role = app_roles::Entity::find()
            .filter(app_roles::Column::ApplicationId.eq(api.id))
            .filter(app_roles::Column::Value.eq(role))
            .one(db)
            .await
            .unwrap()
            .unwrap();
        insert(
            db,
            app_role_assignments::ActiveModel {
                id: Set(Uuid::now_v7()),
                tenant_id: Set(tenant.id),
                resource_application_id: Set(api.id),
                app_role_id: Set(role.id),
                user_id: Set(None),
                group_id: Set(None),
                client_application_id: Set(Some(client.id)),
                ..Default::default()
            },
        )
        .await;
    }
    let issuer = config.issuer(&tenant.slug);
    tokens::issue_app_only(db, &config.master_key, tenant, &issuer, &client, &api)
        .await
        .unwrap()
        .access_token
}

/// A new user holding `roles`.
pub async fn user_with_roles(
    db: &DatabaseConnection,
    tenant_id: Uuid,
    email: &str,
    roles: &[DirectoryRole],
) -> users::Model {
    let user = add_user(db, tenant_id, email, false).await;
    for role in roles {
        directory::assign_directory_role(db, tenant_id, user.id, *role)
            .await
            .unwrap();
    }
    user
}

/// Calls the management API; the body is JSON (or `Null` when empty).
pub async fn call(
    app: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = match body {
        Some(body) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let (status, _, text) = send(app, req).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// RFC 4648 base32 (no padding) decoding, for TOTP secrets shown to users.
pub fn base32_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// A token of a fresh ApplicationAdmin of the fixture tenant.
pub async fn app_admin_token(f: &super::flow::Fixture) -> String {
    let aa = user_with_roles(
        &f.db,
        f.tenant.id,
        &format!("aa-{}@example.com", Uuid::now_v7()),
        &[DirectoryRole::ApplicationAdmin],
    )
    .await;
    mint_user_token(&f.db, &f.config, &f.tenant, &aa).await
}

/// POSTs JSON to the management API.
pub async fn post(
    f: &super::flow::Fixture,
    token: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    call(&f.app, Method::POST, path, Some(token), Some(&body)).await
}
