//! `oauth bootstrap --provisioning-app`: a confidential app holding a role
//! of the tenant's management API (client credentials), so automation can
//! call the management API without a manual admin step. Its secret is
//! printed once: when the app is created or with `--rotate-secret`.

use anyhow::{Context, bail};
use entity::{
    app_role_assignments as ara, app_roles, applications, client_secrets, enums::ClientType,
    tenants,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
};
use serde_json::{Value, json};

use super::{
    OneTimePassword,
    takeover::{Held, Takeover, takeover},
};
use crate::{
    api::{
        app_rules::lock_app,
        applications::{map_write_error, new_row},
        apps_secrets::{self, DEFAULT_DAYS},
        role_assignments::{self, Principal},
        validate,
    },
    audit::{self, Actor, EventType, Target},
    directory::builtin_apps::{MANAGEMENT_API, ROLE_READ_ALL, ROLE_READ_WRITE_ALL},
};

const DISPLAY_NAME: &str = "Provisioning";
/// Description of every secret bootstrap issues; also how it recognises an
/// app it made or adopted (`takeover::Held::bootstrap_marker`).
pub const SECRET_DESCRIPTION: &str = "oauth bootstrap";

/// The management API app role the provisioning app gets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Role {
    /// `Directory.Read.All`.
    Read,
    /// `Directory.ReadWrite.All`: users, groups, memberships, apps and
    /// everything hanging off them — never directory roles or IdPs.
    #[default]
    ReadWrite,
}

impl Role {
    pub fn value(self) -> &'static str {
        match self {
            Self::Read => ROLE_READ_ALL,
            Self::ReadWrite => ROLE_READ_WRITE_ALL,
        }
    }

    /// The role the app must not keep alongside this one: re-running with
    /// `read` downgrades an app that held `read-write`, and vice versa.
    fn other(self) -> Self {
        match self {
            Self::Read => Self::ReadWrite,
            Self::ReadWrite => Self::Read,
        }
    }
}

pub struct Options {
    pub client_id: String,
    pub role: Role,
    /// Issue a new secret for an existing app (older ones stay valid).
    pub rotate_secret: bool,
    /// Allow a [`Takeover`] of an existing app.
    pub adopt: bool,
}

#[derive(Debug)]
pub struct Outcome {
    pub client_id: String,
    pub created: bool,
    /// Why `--adopt-app` was needed, when it was.
    pub adopted: Option<Takeover>,
    pub role: &'static str,
    pub role_assigned: bool,
    /// The other provisioning role, when the app held it until now.
    pub role_removed: Option<&'static str>,
    pub secret: Option<OneTimePassword>,
}

async fn audit(
    conn: &impl ConnectionTrait,
    tenant_id: uuid::Uuid,
    event_type: EventType,
    target: Target,
    details: Value,
) -> anyhow::Result<()> {
    audit::record(
        conn,
        audit::Event {
            tenant_id,
            actor: Actor::System,
            event_type,
            target: Some(target),
            outcome: entity::enums::Outcome::Success,
            ip: None,
            details,
        },
    )
    .await
}

async fn find_app(
    conn: &impl ConnectionTrait,
    tenant_id: uuid::Uuid,
    client_id: &str,
) -> anyhow::Result<Option<applications::Model>> {
    applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant_id))
        .filter(applications::Column::ClientId.eq(client_id))
        .one(conn)
        .await
        .context("looking up application")
}

pub async fn ensure(
    conn: &impl ConnectionTrait,
    tenant: &tenants::Model,
    opts: &Options,
) -> anyhow::Result<Outcome> {
    validate::client_id(&opts.client_id)?;
    let api = find_app(conn, tenant.id, MANAGEMENT_API)
        .await?
        .context("the tenant has no management API app")?;
    let mut adopted = None;
    let (app, created) = match find_app(conn, tenant.id, &opts.client_id).await? {
        Some(app) if app.builtin => bail!("`{}` is a built-in application", opts.client_id),
        Some(app) => {
            let app = lock_app(conn, tenant.id, app.id).await?;
            let held = Held {
                requested: holds(conn, &api, &app, opts.role).await?,
                other: holds(conn, &api, &app, opts.role.other()).await?,
                bootstrap_marker: has_marker(conn, &app).await?,
            };
            // A typo must not hand someone's app the management API, change
            // its access, or give the operator a secret acting as it.
            if let Some(t) = takeover(opts.role, held, opts.rotate_secret) {
                if !opts.adopt {
                    bail!("application `{}` {}", app.client_id, refusal(t));
                }
                adopted = Some(t);
            }
            (app, false)
        }
        None => {
            let mut row = new_row(tenant.id, &opts.client_id, ClientType::Confidential);
            row.display_name = Set(DISPLAY_NAME.to_owned());
            let app = applications::Entity::insert(row)
                .exec_with_returning(conn)
                .await
                .map_err(map_write_error)?;
            let details = json!({ "client_id": app.client_id });
            let target = Target::Application(app.id);
            audit(
                conn,
                tenant.id,
                EventType::ApplicationCreate,
                target,
                details,
            )
            .await?;
            (app, true)
        }
    };
    if app.client_type == ClientType::Public {
        bail!(
            "`{}` is a public client and can't hold a secret",
            app.client_id
        );
    }
    let secret = if created || opts.rotate_secret {
        let (row, value) = apps_secrets::insert(
            conn,
            &app,
            Some(DEFAULT_DAYS),
            Some(SECRET_DESCRIPTION.into()),
            None,
        )
        .await?;
        let details = json!({
            "secret_id": row.id,
            "never_expires": false,
            "caller_supplied": false,
        });
        let target = Target::Application(app.id);
        audit(
            conn,
            tenant.id,
            EventType::ApplicationSecretAdd,
            target,
            details,
        )
        .await?;
        Some(OneTimePassword(value))
    } else {
        None
    };
    let role_assigned = assign_role(conn, tenant, &api, &app, opts.role).await?;
    let other = opts.role.other();
    let role_removed = unassign_role(conn, tenant, &api, &app, other)
        .await?
        .then(|| other.value());
    Ok(Outcome {
        client_id: app.client_id,
        created,
        adopted,
        role: opts.role.value(),
        role_assigned,
        role_removed,
        secret,
    })
}

async fn find_role(
    conn: &impl ConnectionTrait,
    api: &applications::Model,
    role: Role,
) -> anyhow::Result<app_roles::Model> {
    app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(api.id))
        .filter(app_roles::Column::Value.eq(role.value()))
        .one(conn)
        .await?
        .with_context(|| format!("the management API has no role `{}`", role.value()))
}

fn refusal(t: Takeover) -> String {
    let unmarked = format!("was not made by bootstrap (no `{SECRET_DESCRIPTION}` secret)");
    match t {
        Takeover::NoRole => "exists and holds no management API provisioning role; \
             pass --adopt-app to make it the provisioning app"
            .into(),
        Takeover::Upgrade => format!(
            "holds {ROLE_READ_ALL}, which an admin may have given any app; \
             pass --adopt-app to upgrade it to {ROLE_READ_WRITE_ALL}"
        ),
        Takeover::Downgrade => format!(
            "holds {ROLE_READ_WRITE_ALL} and {unmarked}; \
             pass --adopt-app to downgrade it to {ROLE_READ_ALL}"
        ),
        Takeover::RotateSecret => {
            format!("{unmarked}; pass --adopt-app to issue it a new secret")
        }
    }
}

async fn has_marker(
    conn: &impl ConnectionTrait,
    app: &applications::Model,
) -> anyhow::Result<bool> {
    let n = client_secrets::Entity::find()
        .filter(client_secrets::Column::TenantId.eq(app.tenant_id))
        .filter(client_secrets::Column::ApplicationId.eq(app.id))
        .filter(client_secrets::Column::Description.eq(SECRET_DESCRIPTION))
        .count(conn)
        .await
        .context("looking up bootstrap secrets")?;
    Ok(n > 0)
}

async fn holds(
    conn: &impl ConnectionTrait,
    api: &applications::Model,
    app: &applications::Model,
    role: Role,
) -> anyhow::Result<bool> {
    let role = find_role(conn, api, role).await?;
    Ok(find_assignment(conn, &role, app).await?.is_some())
}

async fn find_assignment(
    conn: &impl ConnectionTrait,
    role: &app_roles::Model,
    app: &applications::Model,
) -> anyhow::Result<Option<ara::Model>> {
    ara::Entity::find()
        .filter(ara::Column::AppRoleId.eq(role.id))
        .filter(ara::Column::ClientApplicationId.eq(app.id))
        .one(conn)
        .await
        .context("looking up role assignment")
}

/// True when the assignment was created now.
async fn assign_role(
    conn: &impl ConnectionTrait,
    tenant: &tenants::Model,
    api: &applications::Model,
    app: &applications::Model,
    role: Role,
) -> anyhow::Result<bool> {
    let role = find_role(conn, api, role).await?;
    if find_assignment(conn, &role, app).await?.is_some() {
        return Ok(false);
    }
    let assignment =
        role_assignments::insert(conn, tenant.id, &role, Principal::Application(app.id)).await?;
    let details = json!({
        "resource_client_id": api.client_id,
        "role": role.value,
        "principal_type": "application",
        "principal_id": app.id,
    });
    let target = Target::AppRoleAssignment(assignment.id);
    audit(
        conn,
        tenant.id,
        EventType::RoleAssignmentCreate,
        target,
        details,
    )
    .await?;
    Ok(true)
}

/// True when the app held `role` and no longer does.
async fn unassign_role(
    conn: &impl ConnectionTrait,
    tenant: &tenants::Model,
    api: &applications::Model,
    app: &applications::Model,
    role: Role,
) -> anyhow::Result<bool> {
    let role = find_role(conn, api, role).await?;
    let Some(assignment) = find_assignment(conn, &role, app).await? else {
        return Ok(false);
    };
    ara::Entity::delete_by_id(assignment.id).exec(conn).await?;
    let details = json!({ "resource_client_id": api.client_id, "app_role_id": role.id });
    let target = Target::AppRoleAssignment(assignment.id);
    audit(
        conn,
        tenant.id,
        EventType::RoleAssignmentDelete,
        target,
        details,
    )
    .await?;
    Ok(true)
}
