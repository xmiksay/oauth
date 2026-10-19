//! Login transactions: persistence and the `GET /api/authn/tx/{id}` view.

use anyhow::Context;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use chrono::Duration;
use entity::{
    applications, enums::LoginStage, identity_providers, login_transactions, sessions, users,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::Expr,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    AuthnError, AuthnResult, Outcome, complete,
    cookie::{self, Kind},
    ctx::Ctx,
    ip::ClientIp,
};
use crate::{
    app::AppState, consent::Decision, federation, oidc::params::AuthRequest, secret,
    tenancy::Tenant,
};

pub const TX_TTL_MINUTES: i64 = 15;

pub struct NewTx<'a> {
    pub tenant_id: Uuid,
    pub client_app_id: Uuid,
    pub req: &'a AuthRequest,
    pub stage: LoginStage,
    /// Set for consent-only transactions that reuse an existing session.
    pub session: Option<&'a sessions::Model>,
    /// Value of the browser's transaction-binding cookie.
    pub binding: &'a str,
}

pub async fn create(conn: &impl ConnectionTrait, new: NewTx<'_>) -> anyhow::Result<Uuid> {
    let id = secret::random_uuid()?;
    let now = chrono::Utc::now().fixed_offset();
    let row = login_transactions::ActiveModel {
        id: Set(id),
        tenant_id: Set(new.tenant_id),
        application_id: Set(new.client_app_id),
        params: Set(serde_json::to_value(new.req).context("serializing authorize request")?),
        stage: Set(new.stage),
        user_id: Set(new.session.map(|s| s.user_id)),
        amr: Set(new.session.map(|s| s.amr.clone()).unwrap_or_default()),
        auth_time: Set(new.session.map(|s| s.auth_time)),
        session_id: Set(new.session.map(|s| s.id)),
        binding_hash: Set(secret::hash(new.binding)),
        expires_at: Set(now + Duration::minutes(TX_TTL_MINUTES)),
        ..Default::default()
    };
    login_transactions::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("creating login transaction")?;
    Ok(id)
}

/// A live transaction with its decoded request.
pub struct LoadedTx {
    pub row: login_transactions::Model,
    pub req: AuthRequest,
}

/// Loads a live transaction of this tenant that belongs to this browser.
/// A missing or foreign binding cookie looks exactly like an unknown id, so
/// the endpoint is no oracle for valid transaction ids.
pub async fn load(ctx: &Ctx<'_>, raw_id: &str) -> AuthnResult<LoadedTx> {
    let id = Uuid::parse_str(raw_id).map_err(|_| AuthnError::NotFound)?;
    let now = chrono::Utc::now().fixed_offset();
    let row = login_transactions::Entity::find_by_id(id)
        .filter(login_transactions::Column::TenantId.eq(ctx.tenant.id))
        .one(&ctx.state.db)
        .await?
        .filter(|tx| tx.expires_at > now)
        .filter(|tx| bound_to(ctx, &tx.binding_hash))
        .ok_or(AuthnError::NotFound)?;
    let req =
        serde_json::from_value(row.params.clone()).context("decoding stored authorize request")?;
    Ok(LoadedTx { row, req })
}

pub(super) fn bound_to(ctx: &Ctx<'_>, binding_hash: &[u8]) -> bool {
    cookie::read(ctx.headers, &ctx.state.config, Kind::TxBinding).fold(false, |found, value| {
        secret::ct_eq(&secret::hash(value), binding_hash) | found
    })
}

/// Loads a transaction that must be at `stage`.
pub async fn load_at(ctx: &Ctx<'_>, raw_id: &str, stage: LoginStage) -> AuthnResult<LoadedTx> {
    let tx = load(ctx, raw_id).await?;
    if tx.row.stage != stage {
        return Err(AuthnError::WrongStep);
    }
    Ok(tx)
}

pub async fn user_of(conn: &impl ConnectionTrait, tx: &LoadedTx) -> AuthnResult<users::Model> {
    let id = tx.row.user_id.ok_or(AuthnError::WrongStep)?;
    users::Entity::find_by_id(id)
        .filter(users::Column::TenantId.eq(tx.row.tenant_id))
        .one(conn)
        .await?
        .ok_or(AuthnError::NotFound)
}

/// Moves the transaction from `from` to `to`, recording who signed in. The
/// stage condition makes concurrent submissions advance it at most once.
pub async fn advance(
    conn: &impl ConnectionTrait,
    row: &login_transactions::Model,
    from: LoginStage,
    to: LoginStage,
) -> AuthnResult<()> {
    let result = login_transactions::Entity::update_many()
        .col_expr(login_transactions::Column::Stage, Expr::value(to))
        .col_expr(login_transactions::Column::UserId, Expr::value(row.user_id))
        .col_expr(
            login_transactions::Column::Amr,
            Expr::value(row.amr.clone()),
        )
        .col_expr(
            login_transactions::Column::AuthTime,
            Expr::value(row.auth_time),
        )
        .filter(login_transactions::Column::Id.eq(row.id))
        .filter(login_transactions::Column::Stage.eq(from))
        .exec(conn)
        .await?;
    if result.rows_affected == 1 {
        Ok(())
    } else {
        Err(AuthnError::WrongStep)
    }
}

/// Password → Link: parks the upstream identity on the transaction until a
/// local sign-in links it (CAS on the stage, like [`advance`]).
pub async fn to_link(
    conn: &impl ConnectionTrait,
    id: Uuid,
    pending: &federation::identities::Pending,
) -> AuthnResult<()> {
    let pending = serde_json::to_value(pending).context("serializing pending identity")?;
    let result = login_transactions::Entity::update_many()
        .col_expr(
            login_transactions::Column::Stage,
            Expr::value(LoginStage::Link),
        )
        .col_expr(
            login_transactions::Column::PendingIdentity,
            Expr::value(pending),
        )
        .filter(login_transactions::Column::Id.eq(id))
        .filter(login_transactions::Column::Stage.eq(LoginStage::Password))
        .exec(conn)
        .await?;
    if result.rows_affected == 1 {
        Ok(())
    } else {
        Err(AuthnError::WrongStep)
    }
}

/// Link → Password, dropping the parked identity (its IdP can no longer
/// link). `false` = the transaction had moved on already.
pub async fn unpark(conn: &impl ConnectionTrait, id: Uuid) -> anyhow::Result<bool> {
    let result = login_transactions::Entity::update_many()
        .col_expr(
            login_transactions::Column::Stage,
            Expr::value(LoginStage::Password),
        )
        .col_expr(
            login_transactions::Column::PendingIdentity,
            Expr::value(Option::<serde_json::Value>::None),
        )
        .filter(login_transactions::Column::Id.eq(id))
        .filter(login_transactions::Column::Stage.eq(LoginStage::Link))
        .exec(conn)
        .await
        .context("dropping parked identity")?;
    Ok(result.rows_affected == 1)
}

/// Records which IdP configuration an upstream sign-in went through, for
/// `complete::finish` to re-check.
pub async fn set_federated(
    conn: &impl ConnectionTrait,
    id: Uuid,
    via: &super::federation_pending::IdpRef,
) -> anyhow::Result<serde_json::Value> {
    let value = serde_json::to_value(via).context("serializing federated sign-in")?;
    login_transactions::Entity::update_many()
        .col_expr(
            login_transactions::Column::Federated,
            Expr::value(value.clone()),
        )
        .filter(login_transactions::Column::Id.eq(id))
        .exec(conn)
        .await
        .context("recording federated sign-in")?;
    Ok(value)
}

/// `amr` after a second factor of kind `factor` (`otp`, `hwk`, `swk`): the
/// first factor (`fed` after an upstream sign-in, else `pwd`), the factor,
/// `mfa`.
pub fn with_second_factor(amr: &[String], factor: &str) -> Vec<String> {
    let first = if amr.iter().any(|a| a == "fed") {
        "fed"
    } else {
        "pwd"
    };
    vec![first.to_owned(), factor.to_owned(), "mfa".to_owned()]
}

/// Deletes the transaction if still at `stage`; `false` = someone else
/// already finished it.
pub async fn take(
    conn: &impl ConnectionTrait,
    id: Uuid,
    stage: LoginStage,
) -> anyhow::Result<bool> {
    let result = login_transactions::Entity::delete_many()
        .filter(login_transactions::Column::Id.eq(id))
        .filter(login_transactions::Column::Stage.eq(stage))
        .exec(conn)
        .await
        .context("finishing login transaction")?;
    Ok(result.rows_affected == 1)
}

/// What the login SPA needs to render the current step.
pub async fn view(state: &AppState, tenant: &Tenant, tx: &LoadedTx) -> AuthnResult<Value> {
    let conn = &state.db;
    let client = applications::Entity::find_by_id(tx.row.application_id)
        .one(conn)
        .await?
        .ok_or(AuthnError::NotFound)?;
    let user = match tx.row.user_id {
        Some(_) => Some(user_of(conn, tx).await?),
        None => None,
    };
    let consent = match (&user, tx.row.stage) {
        (Some(user), LoginStage::Consent) => {
            let force = complete::force_consent(&tx.req);
            let eval = complete::evaluate_consent(conn, &client, &tx.req, user.id, force).await?;
            let pending = match &eval.decision {
                Decision::NeedsUser(values) => values.clone(),
                Decision::Granted | Decision::NeedsAdmin(_) => Vec::new(),
            };
            let scopes: Vec<Value> = eval
                .scopes
                .iter()
                .filter(|s| pending.contains(&s.value))
                .map(|s| json!({ "value": s.value, "description": s.description }))
                .collect();
            eval.resource.map(|r| {
                json!({
                    "resource": {
                        "display_name": r.display_name,
                        "audience": crate::oidc::scope::audience(&r),
                    },
                    "scopes": scopes,
                })
            })
        }
        _ => None,
    };
    let idps = federation::idps::enabled(conn, tenant.id).await?;
    let mut stage = tx.row.stage;
    let mut notice = None;
    let mut link = None;
    let brief = |idp: &identity_providers::Model| json!({ "id": idp.id, "name": idp.name });
    if let (Some(raw), LoginStage::Link) = (&tx.row.pending_identity, stage) {
        let pending = super::federation_pending::decode(raw)?;
        match super::federation_pending::usable_idp(conn, tenant.id, &pending).await? {
            Some(idp) => {
                link = Some(json!({
                    "idp": brief(&idp),
                    "email": pending.email,
                    "name": pending.name,
                }));
            }
            // The provider went away while the identity was parked.
            None => {
                unpark(conn, tx.row.id).await?;
                stage = LoginStage::Password;
                notice = Some("link_unavailable");
            }
        }
    }
    let at_password = stage == LoginStage::Password;
    let buttons: Vec<Value> = idps
        .iter()
        .filter(|idp| at_password && idp.visible)
        .map(brief)
        .collect();
    let hint = federation::idps::hinted(&idps, &tx.req).filter(|_| at_password);
    Ok(json!({
        "tx": tx.row.id,
        "step": stage.as_str(),
        "tenant": { "slug": tenant.slug, "display_name": tenant.display_name },
        "client": { "client_id": client.client_id, "display_name": client.display_name },
        "user": user.map(|u| json!({ "email": u.email, "display_name": u.display_name })),
        "consent": consent,
        "factors": super::passkey::factors(state, tx).await?,
        "idps": buttons,
        "idp_hint": hint.map(brief),
        "link": link,
        "notice": notice,
        "features": {
            "password_reset": state.config.email_enabled(),
            "federation": !idps.is_empty(),
        },
    }))
}

pub async fn get(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let tx = load(&ctx, &tx_id).await?;
    Ok(Outcome::Step(view(&state, &tenant, &tx).await?))
}
