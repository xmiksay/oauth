//! `…/me/totp` and `…/me/recovery-codes` — TOTP enrollment and recovery
//! codes. Every change of security info requires the current password
//! (a stolen access token alone can't add, remove or read out a factor).
//! Enrollment is two-step: `POST me/totp` stores a pending secret and shows
//! it once; `POST me/totp/confirm` with a valid code activates it and
//! returns fresh recovery codes (shown once).

use anyhow::anyhow;
use aws_lc_rs::rand;
use axum::{extract::State, http::StatusCode};
use entity::{enums::NotifyEvent, user_recovery_codes, user_totp, users};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait,
    sea_query::Expr,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    Caller,
    extract::Json,
    me::{me, verify_password},
    user_actions::delete_mfa,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authn::{rate_limit, recovery, totp},
    error::{AppError, AppResult},
    notify, secret,
};

const SECRET_BYTES: usize = 20;
const RECOVERY_CODES: usize = 10;
/// Unambiguous lowercase alphabet (no 0/o, 1/l/i): 31 symbols, 12 per code
/// ≈ 59 bits each.
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const RECOVERY_LEN: usize = 12;

/// RFC 4648 base32 without padding (what authenticator apps expect).
fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.extend(
                ALPHABET
                    .get(((buffer >> bits) & 31) as usize)
                    .map(|&c| char::from(c)),
            );
        }
    }
    if bits > 0 {
        out.extend(
            ALPHABET
                .get(((buffer << (5 - bits)) & 31) as usize)
                .map(|&c| char::from(c)),
        );
    }
    out
}

fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    format!(
        "otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={}&period={}",
        enc(issuer),
        enc(account),
        enc(issuer),
        totp::DIGITS,
        totp::STEP_SECS,
    )
}

/// `xxxx-xxxx-xxxx`.
fn recovery_code() -> anyhow::Result<String> {
    let raw = secret::random_string(RECOVERY_ALPHABET, RECOVERY_LEN)?;
    let chunks: Vec<&str> = (0..RECOVERY_LEN)
        .step_by(4)
        .filter_map(|i| raw.get(i..i + 4))
        .collect();
    Ok(chunks.join("-"))
}

/// Replaces the user's recovery codes; returns the new plaintext codes.
async fn replace_recovery_codes(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<String>> {
    user_recovery_codes::Entity::delete_many()
        .filter(user_recovery_codes::Column::TenantId.eq(tenant_id))
        .filter(user_recovery_codes::Column::UserId.eq(user_id))
        .exec(conn)
        .await?;
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    let mut rows = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let code = recovery_code()?;
        rows.push(user_recovery_codes::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(tenant_id),
            user_id: Set(user_id),
            code_hash: Set(recovery::hash(&code)),
            used_at: Set(None),
            ..Default::default()
        });
        codes.push(code);
    }
    user_recovery_codes::Entity::insert_many(rows)
        .exec_without_returning(conn)
        .await?;
    Ok(codes)
}

async fn enrollment(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Option<user_totp::Model>> {
    Ok(user_totp::Entity::find_by_id(user_id)
        .filter(user_totp::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await?)
}

async fn mfa_notice(
    state: &AppState,
    caller: &Caller,
    conn: &impl ConnectionTrait,
    user: &users::Model,
    what: &str,
) -> AppResult<()> {
    let facts = notify::change(what);
    notify::event(
        conn,
        &state.config,
        &caller.tenant,
        user,
        NotifyEvent::MfaChanged,
        &facts,
    )
    .await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordBody {
    password: String,
}

pub async fn begin_totp(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<PasswordBody>,
) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    let existing = enrollment(&state.db, user.tenant_id, user.id).await?;
    if existing.is_some_and(|t| t.confirmed_at.is_some()) {
        return Err(AppError::Conflict(
            "TOTP is already enrolled; remove it first".into(),
        ));
    }
    verify_password(&state, &user, &body.password).await?;
    let mut raw = Zeroizing::new([0u8; SECRET_BYTES]);
    rand::fill(raw.as_mut_slice()).map_err(|_| anyhow!("generating TOTP secret"))?;
    let sealed = totp::seal_secret(
        &state.config.master_key,
        user.tenant_id,
        user.id,
        raw.as_slice(),
    )?;
    // The check above is advisory; `store` is the atomic guard against an
    // enrollment confirmed in the meantime.
    if !totp::store(&state.db, user.tenant_id, user.id, sealed, false).await? {
        return Err(AppError::Conflict(
            "TOTP is already enrolled; remove it first".into(),
        ));
    }
    let secret_b32 = Zeroizing::new(base32(raw.as_slice()));
    Ok(axum::Json(json!({
        "secret": secret_b32.as_str(),
        "otpauth_uri": otpauth_uri(&caller.tenant.display_name, &user.email, &secret_b32),
        "digits": totp::DIGITS,
        "period": totp::STEP_SECS,
        "algorithm": "SHA1",
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeBody {
    code: String,
}

pub async fn confirm_totp(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<CodeBody>,
) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    let pending = enrollment(&state.db, user.tenant_id, user.id)
        .await?
        .filter(|t| t.confirmed_at.is_none())
        .ok_or_else(|| AppError::Conflict("no pending TOTP enrollment".into()))?;
    let key = rate_limit::user_key(user.id);
    let limit = rate_limit::PER_ACCOUNT;
    if let Err(retry_after) =
        rate_limit::hit(&state.db, user.tenant_id, &key, limit, chrono::Utc::now()).await?
    {
        return Err(AppError::RateLimited { retry_after });
    }
    let secret = totp::open_secret(&state.config.master_key, &pending)?;
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let step = totp::verify_code(&secret, &body.code, now, None)
        .ok_or_else(|| AppError::BadRequest("invalid code".into()))?;
    let txn = state.db.begin().await?;
    let confirmed = user_totp::Entity::update_many()
        .col_expr(user_totp::Column::ConfirmedAt, Expr::current_timestamp())
        .col_expr(user_totp::Column::LastUsedStep, Expr::value(step))
        .filter(user_totp::Column::UserId.eq(user.id))
        .filter(user_totp::Column::SecretEnc.eq(pending.secret_enc.clone()))
        .filter(user_totp::Column::ConfirmedAt.is_null())
        .exec(&txn)
        .await?;
    if confirmed.rows_affected != 1 {
        return Err(AppError::Conflict(
            "the TOTP enrollment changed; start again".into(),
        ));
    }
    let codes = replace_recovery_codes(&txn, user.tenant_id, user.id).await?;
    caller
        .audit(
            &txn,
            EventType::MfaTotpEnroll,
            Some(Target::User(user.id)),
            Value::Null,
        )
        .await?;
    mfa_notice(&state, &caller, &txn, &user, "authenticator app added").await?;
    txn.commit().await?;
    Ok(axum::Json(json!({ "recovery_codes": codes })))
}

pub async fn remove_totp(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<PasswordBody>,
) -> AppResult<StatusCode> {
    let user = me(&state, &caller).await?;
    if enrollment(&state.db, user.tenant_id, user.id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound);
    }
    verify_password(&state, &user, &body.password).await?;
    let txn = state.db.begin().await?;
    delete_mfa(&txn, user.tenant_id, user.id).await?;
    caller
        .audit(
            &txn,
            EventType::MfaTotpRemove,
            Some(Target::User(user.id)),
            Value::Null,
        )
        .await?;
    mfa_notice(&state, &caller, &txn, &user, "authenticator app removed").await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<PasswordBody>,
) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    if totp::confirmed(&state.db, user.tenant_id, user.id)
        .await?
        .is_none()
    {
        return Err(AppError::Conflict(
            "recovery codes need an enrolled TOTP authenticator".into(),
        ));
    }
    verify_password(&state, &user, &body.password).await?;
    let txn = state.db.begin().await?;
    let codes = replace_recovery_codes(&txn, user.tenant_id, user.id).await?;
    caller
        .audit(
            &txn,
            EventType::MfaRecoveryCodesRegenerate,
            Some(Target::User(user.id)),
            Value::Null,
        )
        .await?;
    mfa_notice(&state, &caller, &txn, &user, "new recovery codes generated").await?;
    txn.commit().await?;
    Ok(axum::Json(json!({ "recovery_codes": codes })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), expected, "{input}");
        }
    }

    #[test]
    fn otpauth_uri_is_encoded() {
        let uri = otpauth_uri("Contoso Ltd", "ann@example.com", "ABC");
        assert_eq!(
            uri,
            "otpauth://totp/Contoso%20Ltd:ann%40example%2Ecom?secret=ABC&issuer=Contoso%20Ltd\
             &algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn recovery_codes_are_grouped_and_normalize() {
        let code = recovery_code().unwrap();
        assert_eq!(code.len(), 14);
        assert_eq!(code.matches('-').count(), 2);
        assert_eq!(recovery::normalize(&code).len(), RECOVERY_LEN);
        assert_ne!(code, recovery_code().unwrap());
    }
}
