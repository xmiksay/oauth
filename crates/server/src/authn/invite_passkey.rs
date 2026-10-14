//! Accepting an invitation with a passkey instead of a password
//! (`POST /api/authn/email/invite/passkey/options`, `…/passkey`). The link
//! token is the credential, with the same rules as the password variant
//! (`tokens::still_valid`, single use, rollback keeps it unused).

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use entity::{email_tokens, enums::EmailTokenPurpose, users};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait,
};
use serde::Deserialize;
use serde_json::json;

use super::{
    AuthnError, AuthnResult, JsonBody,
    ctx::Ctx,
    email::{limit_links, owner, record},
    ip::ClientIp,
};
use crate::{
    app::AppState,
    audit::EventType,
    mail::tokens,
    oidc::error::no_store,
    passkey::{
        self, PasskeyError, RegistrationJson, Scope,
        store::{self, NewCredential},
    },
    tenancy::Tenant,
};

const INVITE: [EmailTokenPurpose; 1] = [EmailTokenPurpose::Invite];

/// A rejected registration is the client's problem (400), never detailed.
pub(super) fn registration_error(err: PasskeyError) -> AuthnError {
    match err {
        PasskeyError::Internal(err) => AuthnError::Internal(err),
        PasskeyError::Conflict(msg) => AuthnError::Conflict(msg.into()),
        PasskeyError::Invalid(msg) => AuthnError::Invalid(msg.into()),
        _ => AuthnError::Invalid("the passkey could not be registered".into()),
    }
}

#[derive(Deserialize)]
pub struct TokenBody {
    token: String,
}

/// The invited user, if the token may still act on them and they hold no
/// passkey yet (one would already have accepted the invitation).
async fn invited(ctx: &Ctx<'_>, token: &str) -> AuthnResult<(email_tokens::Model, users::Model)> {
    let db = &ctx.state.db;
    let row = tokens::peek(db, ctx.tenant.id, token, &INVITE)
        .await?
        .ok_or(AuthnError::InvalidLink)?;
    let user = users::Entity::find_by_id(row.user_id)
        .filter(users::Column::TenantId.eq(ctx.tenant.id))
        .one(db)
        .await?
        .filter(|u| tokens::still_valid(&row, u))
        .ok_or(AuthnError::InvalidLink)?;
    if store::count(db, ctx.tenant.id, user.id).await? > 0 {
        return Err(AuthnError::InvalidLink);
    }
    Ok((row, user))
}

pub async fn options(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    JsonBody(body): JsonBody<TokenBody>,
) -> AuthnResult<Response> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    limit_links(&ctx).await?;
    let (_, user) = invited(&ctx, &body.token).await?;
    let handle = store::ensure_handle(&state.db, &user).await?;
    let scope = Scope::User {
        purpose: entity::enums::WebauthnPurpose::Register,
        user_id: user.id,
    };
    let challenge = passkey::challenge::issue(&state.db, tenant.id, scope).await?;
    let rp = passkey::rp(&state.config, &tenant.slug);
    let options =
        passkey::wire::creation_options(&rp, &tenant.display_name, &user, &handle, &challenge, &[]);
    Ok(no_store(Json(options).into_response()))
}

#[derive(Deserialize)]
pub struct AcceptBody {
    token: String,
    credential: RegistrationJson,
    name: Option<String>,
}

/// Stores the passkey and marks the address verified (the link proved the
/// mailbox), atomically with consuming the token; the user's other
/// invitations die with it.
pub async fn accept(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    JsonBody(body): JsonBody<AcceptBody>,
) -> AuthnResult<StatusCode> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    limit_links(&ctx).await?;
    let registration = body
        .credential
        .decode()
        .map_err(|_| AuthnError::Invalid("malformed passkey response".into()))?;
    let name = store::name(body.name.as_deref()).map_err(registration_error)?;
    let (peeked, _) = invited(&ctx, &body.token).await?;
    let rp = passkey::rp(&state.config, &tenant.slug);
    let registered =
        passkey::verify_registration(&state.db, &rp, tenant.id, peeked.user_id, &registration)
            .await
            .map_err(registration_error)?;
    let txn = state.db.begin().await?;
    let token = tokens::consume(&txn, tenant.id, &body.token, &INVITE)
        .await?
        .filter(|t| t.id == peeked.id)
        .ok_or(AuthnError::InvalidLink)?;
    let user = owner(&txn, &ctx, &token).await?;
    if store::count(&txn, tenant.id, user.id).await? > 0 {
        return Err(AuthnError::InvalidLink);
    }
    let credential = store::insert(
        &txn,
        NewCredential {
            tenant_id: tenant.id,
            user_id: user.id,
            rp_id: &rp.id,
            registered: &registered,
            transports: registration.transports,
            name,
        },
    )
    .await
    .map_err(registration_error)?;
    tokens::invalidate(&txn, tenant.id, user.id, &INVITE).await?;
    let mut row: users::ActiveModel = user.into();
    row.email_verified = Set(true);
    let user = row.update(&txn).await?;
    let details = json!({ "method": "passkey" });
    record(&txn, &ctx, EventType::UserInviteAccept, user.id, details).await?;
    let details = json!({ "passkey_id": credential.id, "name": credential.name, "via": "invite" });
    record(&txn, &ctx, EventType::MfaPasskeyRegister, user.id, details).await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
