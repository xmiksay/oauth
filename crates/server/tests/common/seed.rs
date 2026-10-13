//! Seeding helpers: apps, scopes, roles, secrets and users inserted
//! directly (the management API arrives in step 4).

use entity::{
    app_role_assignments, app_roles, app_scopes, applications, client_secrets,
    enums::{AccessTokenFormat, ClientType, SigningAlg},
    users,
};
use oauth_server::{
    directory::{self, NewUser},
    secret,
};
use sea_orm::{ActiveValue::Set, DatabaseConnection, EntityTrait};
use uuid::Uuid;

use super::flow::{PASSWORD, SPA_CB, WEB_BYE, WEB_CB};

pub async fn insert<A>(db: &DatabaseConnection, row: A) -> <A::Entity as EntityTrait>::Model
where
    A: sea_orm::ActiveModelTrait + sea_orm::ActiveModelBehavior + Send,
    <A::Entity as EntityTrait>::Model: sea_orm::IntoActiveModel<A>,
{
    A::Entity::insert(row)
        .exec_with_returning(db)
        .await
        .expect("insert")
}

pub async fn add_app(
    db: &DatabaseConnection,
    tenant_id: Uuid,
    client_id: &str,
    client_type: ClientType,
    identifier_uri: Option<&str>,
    format: AccessTokenFormat,
    alg: SigningAlg,
) -> applications::Model {
    insert(
        db,
        applications::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(tenant_id),
            client_id: Set(client_id.into()),
            display_name: Set(format!("{client_id} app")),
            client_type: Set(client_type),
            builtin: Set(false),
            redirect_uris: Set(vec![WEB_CB.into(), SPA_CB.into()]),
            post_logout_redirect_uris: Set(vec![WEB_BYE.into()]),
            identifier_uri: Set(identifier_uri.map(str::to_owned)),
            access_token_format: Set(format),
            signing_alg: Set(alg),
            ..Default::default()
        },
    )
    .await
}

pub async fn add_scope(
    db: &DatabaseConnection,
    app: &applications::Model,
    value: &str,
    admin: bool,
) {
    insert(
        db,
        app_scopes::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(app.tenant_id),
            application_id: Set(app.id),
            value: Set(value.into()),
            description: Set(format!("{value} description")),
            admin_consent_required: Set(admin),
            ..Default::default()
        },
    )
    .await;
}

pub async fn add_role(
    db: &DatabaseConnection,
    app: &applications::Model,
    value: &str,
    member: &str,
) -> Uuid {
    insert(
        db,
        app_roles::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(app.tenant_id),
            application_id: Set(app.id),
            value: Set(value.into()),
            display_name: Set(value.into()),
            description: Set(String::new()),
            allowed_member_types: Set(vec![member.into()]),
            ..Default::default()
        },
    )
    .await
    .id
}

pub async fn assign_role(
    db: &DatabaseConnection,
    resource: &applications::Model,
    role_id: Uuid,
    group: Option<Uuid>,
    client: Option<Uuid>,
) {
    insert(
        db,
        app_role_assignments::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(resource.tenant_id),
            resource_application_id: Set(resource.id),
            app_role_id: Set(role_id),
            user_id: Set(None),
            group_id: Set(group),
            client_application_id: Set(client),
            ..Default::default()
        },
    )
    .await;
}

pub async fn add_secret(db: &DatabaseConnection, app: &applications::Model) -> String {
    let value = secret::random_token().unwrap();
    insert(
        db,
        client_secrets::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(app.tenant_id),
            application_id: Set(app.id),
            secret_hash: Set(secret::hash(&value)),
            hint: Set(value[..3].to_owned()),
            description: Set(None),
            expires_at: Set(None),
            ..Default::default()
        },
    )
    .await;
    value
}

pub async fn add_user(
    db: &DatabaseConnection,
    tenant_id: Uuid,
    email: &str,
    must_change: bool,
) -> users::Model {
    directory::create_user(
        db,
        tenant_id,
        NewUser {
            email,
            display_name: "Test User",
            password: Some(PASSWORD),
            must_change_password: must_change,
        },
    )
    .await
    .unwrap()
}
