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
    device, device_code,
    ip::ClientIp,
    mfa_policy,
    session::{self, NewSession},
    tx::{self, LoadedTx},
};
use crate::{
    app::AppState,
    consent::{self, Decision},
    metrics,
    oidc::{
        assignment,
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
}

/// The resource app a pending request names (`req.resource_id`), loaded
/// once per step and shared by the assignment and consent checks.
pub async fn pending_resource(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    resource_id: Option<Uuid>,
) -> anyhow::Result<Option<applications::Model>> {
    let Some(resource_id) = resource_id else {
        return Ok(None);
    };
    let resource = applications::Entity::find_by_id(resource_id)
        .filter(applications::Column::TenantId.eq(client.tenant_id))
        .one(conn)
        .await
        .context("loading resource app")?
        .context("resource app of a pending request vanished")?;
    Ok(Some(resource))
}

/// Consent state of `req` (whose resource is `resource`, from
/// [`pending_resource`]) for `user_id`. Built-in clients are pre-consented.
pub async fn evaluate_consent(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    req: &AuthRequest,
    resource: Option<&applications::Model>,
    user_id: Uuid,
    force: bool,
) -> anyhow::Result<ConsentEval> {
    let Some(resource) = resource else {
        return Ok(ConsentEval {
            decision: Decision::Granted,
            scopes: Vec::new(),
        });
    };
    let scopes = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(resource.id))
        .filter(app_scopes::Column::Value.is_in(req.resource_scopes.clone()))
        .all(conn)
        .await
        .context("loading requested scopes")?;
    let decision = if client.builtin {
        Decision::Granted
    } else {
        let granted =
            consent::granted_scopes(conn, client.tenant_id, client.id, resource.id, user_id)
                .await?;
        consent::evaluate(&scopes, &granted, force)
    };
    Ok(ConsentEval { decision, scopes })
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
    // MFA policy: a sign-in that isn't multi-factor yet goes through the
    // user's second factor (or its enrolment) before anything else.
    let next = match next {
        Some(LoginStage::Mfa | LoginStage::MfaEnroll) => next,
        _ => {
            let app = tx.row.application_id;
            let amr = &tx.row.amr;
            let missing =
                mfa_policy::missing(ctx.state, ctx.tenant, app, &tx.req, user.id, amr).await?;
            // The policy was tightened while the consent screen was up. A
            // consent-only transaction can't step up from here (`finish`
            // would reuse its single-factor session): a new request does.
            if missing.is_some() && from == LoginStage::Consent {
                close(ctx, &tx, from, user.id, "mfa_required").await?;
                let msg = "multi-factor authentication is now required; sign in again";
                return ctx.error_redirect(&tx.req, ErrorCode::LoginRequired, msg);
            }
            missing.or(next)
        }
    };
    if let Some(stage) = next {
        tx::advance(conn, &tx.row, from, stage).await?;
        tx.row.stage = stage;
        return Ok(Outcome::Step(tx::view(ctx.state, ctx.tenant, &tx).await?));
    }
    let client = client_of(conn, &tx).await?;
    let resource = pending_resource(conn, &client, tx.req.resource_id).await?;
    let resource = resource.as_ref();
    if !assignment::user_may_use(conn, client.tenant_id, user.id, &client, resource).await? {
        tx::take(conn, tx.row.id, from).await?;
        return ctx.error_redirect(&tx.req, ErrorCode::AccessDenied, assignment::NOT_ASSIGNED);
    }
    let force = force_consent(&tx.req) && !just_consented;
    let eval = evaluate_consent(conn, &client, &tx.req, resource, user.id, force).await?;
    // A device request is always confirmed explicitly (consent alone
    // would let a phished user code through silently).
    let confirm_device = tx.req.device.is_some() && !just_consented;
    match eval.decision {
        Decision::NeedsAdmin(values) => {
            close(ctx, &tx, from, user.id, "admin_consent_required").await?;
            let description = format!("admin approval required for: {}", values.join(" "));
            let code = match tx.req.device {
                Some(_) => ErrorCode::ConsentRequired,
                None => ErrorCode::AccessDenied,
            };
            ctx.error_redirect(&tx.req, code, &description)
        }
        Decision::Granted if !confirm_device => finish(ctx, tx, from, user).await,
        Decision::NeedsUser(_) | Decision::Granted => {
            if from != LoginStage::Consent {
                tx::advance(conn, &tx.row, from, LoginStage::Consent).await?;
            }
            tx.row.stage = LoginStage::Consent;
            Ok(Outcome::Step(tx::view(ctx.state, ctx.tenant, &tx).await?))
        }
    }
}

/// Claims the transaction without issuing anything and, for a device
/// request, denies the device code with its audit event — in one DB
/// transaction, so a refused device never keeps polling
/// `authorization_pending` after its login transaction is gone.
async fn close(
    ctx: &Ctx<'_>,
    tx: &LoadedTx,
    from: LoginStage,
    user_id: Uuid,
    reason: &'static str,
) -> AuthnResult<()> {
    let txn = ctx.state.db.begin().await?;
    if tx::take(&txn, tx.row.id, from).await? {
        device_code::deny_for(&txn, ctx, tx, user_id, reason).await?;
    }
    txn.commit().await?;
    Ok(())
}

/// Claims the transaction, creates (or reuses) the session and issues the
/// code — atomically, so a failure leaves neither a half-made session nor a
/// burnt transaction behind.
async fn finish(
    ctx: &Ctx<'_>,
    tx: LoadedTx,
    from: LoginStage,
    user: &users::Model,
) -> AuthnResult<Outcome> {
    let config = &ctx.state.config;
    let txn = ctx.state.db.begin().await?;
    // Before the transaction row: IdP rows are always locked first.
    if let Some(idp_id) = super::federation_pending::lock_first(&txn, ctx, &tx.row).await? {
        drop(txn);
        super::federation_pending::refuse_changed(ctx, &tx, user.id, idp_id).await?;
        return Err(AuthnError::Upstream);
    }
    // Claim the transaction first: a concurrent duplicate gets no second code.
    if !tx::take(&txn, tx.row.id, from).await? {
        return Err(AuthnError::WrongStep);
    }
    let mut cookies = Vec::new();
    // The session this transaction builds on (consent-only or step-up) must
    // still be live: a sign-out or revocation meanwhile ends the sign-in.
    let origin = match tx.row.session_id {
        Some(id) => match session::lock_live(&txn, ctx.tenant.id, id).await? {
            Some(existing) if existing.user_id == user.id => Some(existing),
            _ => {
                device_code::deny_for(&txn, ctx, &tx, user.id, "session_ended").await?;
                txn.commit().await?;
                let msg = "the session ended while the sign-in was pending";
                return ctx.error_redirect(&tx.req, ErrorCode::LoginRequired, msg);
            }
        },
        None => None,
    };
    let session = match origin {
        Some(existing) if !tx.row.step_up => existing,
        origin => {
            let user_id = tx
                .row
                .user_id
                .filter(|id| *id == user.id)
                .ok_or(AuthnError::WrongStep)?;
            // Whatever other session the browser's cookie names (another
            // account meanwhile) is replaced.
            if let Some(old) = session::from_cookie(&txn, config, ctx.tenant, ctx.headers).await?
                && origin.as_ref().is_none_or(|o| o.id != old.id)
            {
                session::delete(&txn, old.id).await?;
            }
            let (created, token) = match origin {
                // A step-up keeps the session it continued (so `sid` and
                // the session's refresh tokens stay bound to it); the
                // second factor was just verified, so `auth_time` is now.
                Some(old) => {
                    let now = chrono::Utc::now().fixed_offset();
                    session::step_up(&txn, config, old, &tx.row.amr, now).await?
                }
                // A fresh sign-in (prompt=login, max_age, another account).
                None => {
                    let auth_time = tx.row.auth_time.ok_or(AuthnError::WrongStep)?;
                    let new = NewSession {
                        tenant_id: ctx.tenant.id,
                        user_id,
                        amr: &tx.row.amr,
                        auth_time,
                        ip: ctx.ip,
                        user_agent: ctx.user_agent,
                        min_expires_at: None,
                    };
                    session::create(&txn, config, new).await?
                }
            };
            cookies.push(cookie::set(config, Kind::Session, &token)?);
            cookies.push(device::on_sign_in(&txn, ctx, user).await?);
            let details = json!({
                "session_id": created.id,
                "application_id": tx.row.application_id,
                "amr": created.amr,
            });
            ctx.audit_sign_in(&txn, Some(user_id), AuditOutcome::Success, details)
                .await?;
            // A link-stage sign-in links the pending identity atomically
            // with completing it. The user did authenticate locally, so a
            // link that can't be made any more doesn't fail the sign-in.
            if let Some(pending) = &tx.row.pending_identity {
                super::federation_pending::link_or_skip(&txn, ctx, pending, user).await?;
            }
            created
        }
    };
    let url = match tx.req.device {
        Some(device_id) => {
            let app = tx.row.application_id;
            match device_code::approve(&txn, ctx, device_id, app, &session).await? {
                true => device_code::result_url(ctx, "result=approved"),
                false => device_code::result_url(ctx, "error=expired_token"),
            }
        }
        None => {
            tokens::code::issue_redirect(
                &txn,
                &ctx.issuer(),
                tx.row.application_id,
                &tx.req,
                &session,
            )
            .await?
        }
    };
    txn.commit().await?;
    if tx.row.session_id.is_none() || tx.row.step_up {
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
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<ConsentBody>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let tx = tx::load_at(&ctx, &tx_id, LoginStage::Consent).await?;
    let user = tx::user_of(conn, &tx).await?;
    if !body.approve {
        close(&ctx, &tx, LoginStage::Consent, user.id, "declined").await?;
        let msg = "the user declined to consent";
        return ctx.error_redirect(&tx.req, ErrorCode::AccessDenied, msg);
    }
    let client = client_of(conn, &tx).await?;
    let resource = pending_resource(conn, &client, tx.req.resource_id).await?;
    let force = force_consent(&tx.req);
    let eval = evaluate_consent(conn, &client, &tx.req, resource.as_ref(), user.id, force).await?;
    if let (Decision::NeedsUser(pending), Some(resource)) = (&eval.decision, &resource) {
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
