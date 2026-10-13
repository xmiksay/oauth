//! After a step succeeds: pick the next step, evaluate consent, and finally
//! create the session and redirect back to the client with a code.

use anyhow::Context;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use entity::{
    app_scopes, applications,
    enums::{LoginStage, Outcome as AuditOutcome},
    users,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome,
    cookie::{self, Kind},
    ctx::Ctx,
    ip::ClientIp,
    session::{self, NewSession},
    tx::{self, LoadedTx},
};
use crate::{
    app::AppState,
    consent::{self, Decision},
    metrics,
    oidc::{
        error::ErrorCode,
        params::{AuthRequest, Prompt},
    },
    tenancy::Tenant,
    tokens,
};

pub fn force_consent(req: &AuthRequest) -> bool {
    req.prompt == Some(Prompt::Consent)
}

pub struct ConsentEval {
    pub decision: Decision,
    /// The requested scopes of the resource.
    pub scopes: Vec<app_scopes::Model>,
    pub resource: Option<applications::Model>,
}

/// Consent state of `req` for `user_id`. Built-in clients are pre-consented.
pub async fn evaluate_consent(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    req: &AuthRequest,
    user_id: Uuid,
    force: bool,
) -> anyhow::Result<ConsentEval> {
    let Some(resource_id) = req.resource_id else {
        return Ok(ConsentEval {
            decision: Decision::Granted,
            scopes: Vec::new(),
            resource: None,
        });
    };
    let resource = applications::Entity::find_by_id(resource_id)
        .filter(applications::Column::TenantId.eq(client.tenant_id))
        .one(conn)
        .await
        .context("loading resource app")?
        .context("resource app of a pending request vanished")?;
    let scopes = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(resource_id))
        .filter(app_scopes::Column::Value.is_in(req.resource_scopes.clone()))
        .all(conn)
        .await
        .context("loading requested scopes")?;
    let decision = if client.builtin {
        Decision::Granted
    } else {
        let granted =
            consent::granted_scopes(conn, client.tenant_id, client.id, resource_id, user_id)
                .await?;
        consent::evaluate(&scopes, &granted, force)
    };
    Ok(ConsentEval {
        decision,
        scopes,
        resource: Some(resource),
    })
}

async fn client_of(conn: &impl ConnectionTrait, tx: &LoadedTx) -> AuthnResult<applications::Model> {
    applications::Entity::find_by_id(tx.row.application_id)
        .one(conn)
        .await?
        .ok_or(AuthnError::NotFound)
}

/// Continues a transaction whose step `from` just succeeded (`tx.row` holds
/// the updated user / amr / auth_time). `next` = a further sign-in step;
/// `None` = sign-in is complete, go on to consent and the code.
pub async fn proceed(
    ctx: &Ctx<'_>,
    mut tx: LoadedTx,
    from: LoginStage,
    next: Option<LoginStage>,
    user: &users::Model,
    just_consented: bool,
) -> AuthnResult<Outcome> {
    let conn = &ctx.state.db;
    if user.disabled {
        return Err(AuthnError::AccountDisabled);
    }
    if let Some(stage) = next {
        tx::advance(conn, &tx.row, from, stage).await?;
        tx.row.stage = stage;
        return Ok(Outcome::Step(tx::view(ctx.state, ctx.tenant, &tx).await?));
    }
    let client = client_of(conn, &tx).await?;
    let force = force_consent(&tx.req) && !just_consented;
    let eval = evaluate_consent(conn, &client, &tx.req, user.id, force).await?;
    match eval.decision {
        Decision::NeedsAdmin(values) => {
            tx::take(conn, tx.row.id, from).await?;
            let description = format!("admin approval required for: {}", values.join(" "));
            ctx.error_redirect(&tx.req, ErrorCode::AccessDenied, &description)
        }
        Decision::NeedsUser(_) => {
            if from != LoginStage::Consent {
                tx::advance(conn, &tx.row, from, LoginStage::Consent).await?;
            }
            tx.row.stage = LoginStage::Consent;
            Ok(Outcome::Step(tx::view(ctx.state, ctx.tenant, &tx).await?))
        }
        Decision::Granted => finish(ctx, tx, from).await,
    }
}

/// Claims the transaction, creates (or reuses) the session and issues the
/// code — atomically, so a failure leaves neither a half-made session nor a
/// burnt transaction behind.
async fn finish(ctx: &Ctx<'_>, tx: LoadedTx, from: LoginStage) -> AuthnResult<Outcome> {
    let config = &ctx.state.config;
    let slug = &ctx.tenant.slug;
    let txn = ctx.state.db.begin().await?;
    // Claim the transaction first: a concurrent duplicate gets no second code.
    if !tx::take(&txn, tx.row.id, from).await? {
        return Err(AuthnError::WrongStep);
    }
    let mut cookies = Vec::new();
    let session = match tx.row.session_id {
        Some(id) => match session::find_by_id(&txn, ctx.tenant.id, id).await? {
            Some(existing) => existing,
            None => {
                txn.commit().await?;
                let msg = "the session ended while consent was pending";
                return ctx.error_redirect(&tx.req, ErrorCode::LoginRequired, msg);
            }
        },
        None => {
            let user_id = tx.row.user_id.ok_or(AuthnError::WrongStep)?;
            let auth_time = tx.row.auth_time.ok_or(AuthnError::WrongStep)?;
            // A fresh sign-in (prompt=login, max_age, another account)
            // replaces whatever session this browser had.
            if let Some(old) = session::from_cookie(&txn, config, ctx.tenant, ctx.headers).await? {
                session::delete(&txn, old.id).await?;
            }
            let (created, token) = session::create(
                &txn,
                config,
                NewSession {
                    tenant_id: ctx.tenant.id,
                    user_id,
                    amr: &tx.row.amr,
                    auth_time,
                    ip: ctx.ip,
                    user_agent: ctx.user_agent,
                },
            )
            .await?;
            cookies.push(cookie::set(config, Kind::Session, slug, &token)?);
            let details = json!({
                "session_id": created.id,
                "application_id": tx.row.application_id,
                "amr": created.amr,
            });
            ctx.audit_sign_in(&txn, Some(user_id), AuditOutcome::Success, details)
                .await?;
            created
        }
    };
    let url = tokens::code::issue_redirect(
        &txn,
        &ctx.issuer(),
        tx.row.application_id,
        &tx.req,
        &session,
    )
    .await?;
    txn.commit().await?;
    if tx.row.session_id.is_none() {
        metrics::login("success");
    }
    Ok(Outcome::Redirect { url, cookies })
}

#[derive(Deserialize)]
pub struct ConsentBody {
    approve: bool,
    /// Must list every scope shown on the consent screen when approving
    /// (consent is all-or-nothing, as in Entra).
    #[serde(default)]
    scopes: Vec<String>,
}

pub async fn consent(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path((_, tx_id)): Path<(String, String)>,
    JsonBody(body): JsonBody<ConsentBody>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let tx = tx::load_at(&ctx, &tx_id, LoginStage::Consent).await?;
    let user = tx::user_of(conn, &tx).await?;
    if !body.approve {
        tx::take(conn, tx.row.id, LoginStage::Consent).await?;
        let msg = "the user declined to consent";
        return ctx.error_redirect(&tx.req, ErrorCode::AccessDenied, msg);
    }
    let client = client_of(conn, &tx).await?;
    let eval = evaluate_consent(conn, &client, &tx.req, user.id, force_consent(&tx.req)).await?;
    if let (Decision::NeedsUser(pending), Some(resource)) = (&eval.decision, &eval.resource) {
        if !pending.iter().all(|p| body.scopes.contains(p)) {
            return Err(AuthnError::Invalid(
                "approve every listed scope or decline".into(),
            ));
        }
        consent::store_grant(
            conn,
            tenant.id,
            client.id,
            resource.id,
            Some(user.id),
            pending,
        )
        .await?;
    }
    proceed(&ctx, tx, LoginStage::Consent, None, &user, true).await
}
