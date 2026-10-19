//! `federation_states`: one row per upstream round trip, created when the
//! browser is sent upstream and consumed (deleted, single use) when it comes
//! back. The `state` is a bearer value stored as its SHA-256; the PKCE
//! verifier is sealed to its row.

use anyhow::Context;
use chrono::Duration;
use entity::{enums::FederationPurpose, federation_states};
use sea_orm::{ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{keys::wrap, oidc::pkce, secret};

pub const STATE_TTL_MINUTES: i64 = 10;

/// Whose round trip this is.
pub enum Owner {
    /// Signing in within login transaction `tx_id`.
    Login { tx_id: Uuid },
    /// User `user_id` linking from My Account, signed in with `session_id`.
    Link { user_id: Uuid, session_id: Uuid },
}

pub struct NewState<'a> {
    pub tenant_id: Uuid,
    pub idp_id: Uuid,
    /// The IdP's `generation` now; the callback requires it unchanged.
    pub idp_generation: i64,
    pub owner: Owner,
    /// SHA-256 of the browser's tx-binding cookie.
    pub binding_hash: &'a [u8],
}

/// What goes into the upstream authorization request.
pub struct Started {
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
}

/// Creates the state, replacing any earlier one of the same transaction (or
/// the same user's earlier link attempt), so repeated clicks can't pile up
/// rows.
pub async fn create(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    new: NewState<'_>,
) -> anyhow::Result<Started> {
    use federation_states::Column;
    let (purpose, tx_id, user_id, session_id) = match new.owner {
        Owner::Login { tx_id } => (FederationPurpose::Login, Some(tx_id), None, None),
        Owner::Link {
            user_id,
            session_id,
        } => (
            FederationPurpose::Link,
            None,
            Some(user_id),
            Some(session_id),
        ),
    };
    let earlier = federation_states::Entity::delete_many()
        .filter(Column::TenantId.eq(new.tenant_id))
        .filter(Column::Purpose.eq(purpose));
    let earlier = match (tx_id, user_id) {
        (Some(tx), _) => earlier.filter(Column::TxId.eq(tx)),
        (None, user) => earlier.filter(Column::UserId.eq(user)),
    };
    earlier
        .exec(conn)
        .await
        .context("replacing earlier federation state")?;
    let id = Uuid::now_v7();
    let state = secret::random_token()?;
    let nonce = secret::random_token()?;
    let verifier = Zeroizing::new(secret::random_token()?);
    let sealed = wrap::seal(
        master_key,
        &wrap::pkce_aad(new.tenant_id, id),
        verifier.as_bytes(),
    )?;
    let now = chrono::Utc::now().fixed_offset();
    let row = federation_states::ActiveModel {
        id: Set(id),
        tenant_id: Set(new.tenant_id),
        tx_id: Set(tx_id),
        idp_id: Set(new.idp_id),
        state_hash: Set(secret::hash(&state)),
        binding_hash: Set(new.binding_hash.to_vec()),
        nonce: Set(nonce.clone()),
        pkce_verifier_sealed: Set(sealed),
        idp_generation: Set(new.idp_generation),
        purpose: Set(purpose),
        user_id: Set(user_id),
        session_id: Set(session_id),
        created_at: Set(now),
        expires_at: Set(now + Duration::minutes(STATE_TTL_MINUTES)),
    };
    federation_states::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("storing federation state")?;
    Ok(Started {
        state,
        nonce,
        code_challenge: pkce::challenge_for(&verifier),
    })
}

/// A consumed state with its unsealed PKCE verifier.
pub struct Consumed {
    pub row: federation_states::Model,
    pub verifier: Zeroizing<String>,
}

/// Deletes the state `raw` names in this tenant and returns it if it was
/// still live. The DELETE is the single-use check: of two concurrent
/// callbacks with the same state, only one gets the row.
pub async fn consume(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    tenant_id: Uuid,
    raw: &str,
) -> anyhow::Result<Option<Consumed>> {
    use federation_states::Column;
    let rows = federation_states::Entity::delete_many()
        .filter(Column::TenantId.eq(tenant_id))
        .filter(Column::StateHash.eq(secret::hash(raw)))
        .exec_with_returning(conn)
        .await
        .context("consuming federation state")?;
    let now = chrono::Utc::now().fixed_offset();
    let Some(row) = rows.into_iter().find(|r| r.expires_at > now) else {
        return Ok(None);
    };
    let plain = wrap::open(
        master_key,
        &wrap::pkce_aad(row.tenant_id, row.id),
        &row.pkce_verifier_sealed,
    )?;
    let verifier = Zeroizing::new(
        String::from_utf8(plain.to_vec()).context("sealed PKCE verifier is not UTF-8")?,
    );
    Ok(Some(Consumed { row, verifier }))
}
