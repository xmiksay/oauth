//! Built-in app registrations every tenant gets: the management API (resource)
//! and the two first-party SPAs that call it, pre-consented tenant-wide.

use anyhow::Context;
use entity::{
    app_required_permissions, app_roles, app_scopes, applications, consent_grants,
    enums::{AccessTokenFormat, ClientType, SigningAlg, member_type},
    tenants,
};
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use uuid::Uuid;

pub const MANAGEMENT_API: &str = "management-api";
pub const ADMIN_PORTAL: &str = "admin-portal";
pub const MY_ACCOUNT: &str = "my-account";

pub const SCOPE_ACCESS_AS_USER: &str = "Directory.AccessAsUser";
pub const ROLE_READ_ALL: &str = "Directory.Read.All";
pub const ROLE_READ_WRITE_ALL: &str = "Directory.ReadWrite.All";

/// SPA refresh tokens live in browser storage; cap them at 24 h like Entra.
const SPA_REFRESH_TTL_SECS: i32 = 24 * 3600;

/// (client_id, display name, SPA area path segment).
const SPAS: [(&str, &str, &str); 2] = [
    (ADMIN_PORTAL, "Admin portal", "admin"),
    (MY_ACCOUNT, "My Account", "myaccount"),
];

fn application(
    tenant_id: Uuid,
    client_id: &str,
    name: &str,
    client_type: ClientType,
) -> applications::ActiveModel {
    applications::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        client_id: Set(client_id.to_owned()),
        display_name: Set(name.to_owned()),
        client_type: Set(client_type),
        builtin: Set(true),
        redirect_uris: Set(Vec::new()),
        post_logout_redirect_uris: Set(Vec::new()),
        identifier_uri: Set(None),
        access_token_format: Set(AccessTokenFormat::Jwt),
        signing_alg: Set(SigningAlg::Rs256),
        ..Default::default()
    }
}

async fn insert<A>(
    conn: &impl ConnectionTrait,
    row: A,
    what: &str,
) -> anyhow::Result<<A::Entity as EntityTrait>::Model>
where
    A: sea_orm::ActiveModelTrait + sea_orm::ActiveModelBehavior + Send,
    <A::Entity as EntityTrait>::Model: sea_orm::IntoActiveModel<A>,
{
    A::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .with_context(|| format!("inserting built-in {what}"))
}

pub async fn provision(
    conn: &impl ConnectionTrait,
    public_url: &str,
    tenant: &tenants::Model,
) -> anyhow::Result<()> {
    let tid = tenant.id;
    let mut api = application(
        tid,
        MANAGEMENT_API,
        "Management API",
        ClientType::Confidential,
    );
    api.identifier_uri = Set(Some(format!("api://{MANAGEMENT_API}")));
    let api = insert(conn, api, "management API").await?;

    let scope = app_scopes::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tid),
        application_id: Set(api.id),
        value: Set(SCOPE_ACCESS_AS_USER.to_owned()),
        description: Set("Manage the directory as the signed-in user".to_owned()),
        admin_consent_required: Set(true),
        ..Default::default()
    };
    let scope = insert(conn, scope, "scope").await?;

    for (value, name) in [
        (ROLE_READ_ALL, "Read directory data"),
        (ROLE_READ_WRITE_ALL, "Read and write directory data"),
    ] {
        let role = app_roles::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(tid),
            application_id: Set(api.id),
            value: Set(value.to_owned()),
            display_name: Set(name.to_owned()),
            description: Set(format!("{name} without a signed-in user")),
            allowed_member_types: Set(vec![member_type::APPLICATION.to_owned()]),
            ..Default::default()
        };
        insert(conn, role, "app role").await?;
    }

    for (client_id, name, area) in SPAS {
        let base = format!("{public_url}/{}/{area}", tenant.slug);
        let mut spa = application(tid, client_id, name, ClientType::Public);
        spa.redirect_uris = Set(vec![format!("{base}/callback")]);
        spa.post_logout_redirect_uris = Set(vec![base]);
        spa.refresh_token_ttl_secs = Set(SPA_REFRESH_TTL_SECS);
        let spa = insert(conn, spa, name).await?;

        let permission = app_required_permissions::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(tid),
            application_id: Set(spa.id),
            resource_application_id: Set(api.id),
            scope_id: Set(Some(scope.id)),
            app_role_id: Set(None),
            ..Default::default()
        };
        insert(conn, permission, "required permission").await?;

        let consent = consent_grants::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(tid),
            client_application_id: Set(spa.id),
            resource_application_id: Set(api.id),
            user_id: Set(None),
            scopes: Set(vec![SCOPE_ACCESS_AS_USER.to_owned()]),
            ..Default::default()
        };
        insert(conn, consent, "admin consent").await?;
    }
    Ok(())
}
