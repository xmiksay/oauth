//! Passkey ceremonies over the database: challenges, stored credentials
//! and the glue around the pure `webauthn` verifier. Callers (login API,
//! My Account, invitations, admin) map [`PasskeyError`] to their own error
//! type and audit with [`PasskeyError::reason`].
//!
//! Every ceremony consumes its challenge before anything else is checked,
//! on its own statement: a failed attempt still burns it.

pub mod challenge;
pub mod store;
pub mod wire;

use entity::webauthn_credentials;
use sea_orm::ConnectionTrait;
use uuid::Uuid;

pub use challenge::Scope;
pub use wire::{Assertion, AssertionJson, Registration, RegistrationJson, rp};

use crate::{
    secret,
    webauthn::{
        Rp, WebauthnError,
        assert::{self, Asserted, Stored},
        cose::CoseKey,
        register::{self, Registered},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("passkey rejected: {0}")]
    Rejected(WebauthnError),
    #[error("unknown, expired or already used challenge")]
    Challenge,
    #[error("unknown passkey")]
    UnknownCredential,
    #[error("passkey of another account")]
    ForeignCredential,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Conflict(&'static str),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<WebauthnError> for PasskeyError {
    fn from(err: WebauthnError) -> Self {
        Self::Rejected(err)
    }
}

impl PasskeyError {
    /// Fixed code for audit details.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Rejected(err) => err.reason(),
            Self::Challenge => "invalid_challenge",
            Self::UnknownCredential => "unknown_credential",
            Self::ForeignCredential => "foreign_credential",
            Self::Invalid(_) => "invalid",
            Self::Conflict(_) => "conflict",
            Self::Internal(_) => "internal",
        }
    }

    pub fn is_sign_count_regression(&self) -> bool {
        matches!(self, Self::Rejected(WebauthnError::SignCountRegression))
    }
}

/// Who may answer an assertion.
#[derive(Clone, Copy, Debug)]
pub enum Owner<'a> {
    /// A credential of this user (MFA step, re-authentication).
    User(Uuid),
    /// Whoever the credential belongs to (passwordless sign-in): the
    /// response's user handle must be that user's handle.
    Handle(Option<&'a [u8]>),
}

pub struct Verified {
    pub credential: webauthn_credentials::Model,
    pub asserted: Asserted,
}

/// RFC 8176 `amr` for a passkey: `swk` for a synced (backup-eligible)
/// key, `hwk` for one bound to its device.
pub fn amr(credential: &webauthn_credentials::Model) -> &'static str {
    if credential.backup_eligible {
        "swk"
    } else {
        "hwk"
    }
}

/// Verifies `assertion` against `credential` (looked up by the caller
/// from `assertion.credential_id`, so it could rate-limit on its owner)
/// and records its use.
pub async fn verify_assertion(
    conn: &impl ConnectionTrait,
    rp: &Rp,
    tenant_id: Uuid,
    assertion: &Assertion,
    scope: Scope,
    credential: Option<webauthn_credentials::Model>,
    owner: Owner<'_>,
) -> Result<Verified, PasskeyError> {
    let consumed =
        challenge::consume(conn, tenant_id, &assertion.client_data.challenge, scope).await?;
    if consumed.is_none() {
        return Err(PasskeyError::Challenge);
    }
    let credential = credential
        .filter(|c| c.tenant_id == tenant_id && c.credential_id == assertion.credential_id)
        .ok_or(PasskeyError::UnknownCredential)?;
    let owned = match owner {
        Owner::User(user_id) => credential.user_id == user_id,
        Owner::Handle(handle) => match (handle, &assertion.user_handle) {
            (Some(expected), Some(given)) => secret::ct_eq(expected, given),
            _ => false,
        },
    };
    if !owned {
        return Err(PasskeyError::ForeignCredential);
    }
    let key = CoseKey::parse(&credential.public_key)?;
    let stored = Stored {
        key: &key,
        sign_count: u32::try_from(credential.sign_count).unwrap_or(u32::MAX),
        backup_eligible: credential.backup_eligible,
    };
    let asserted = assert::verify(
        rp,
        &assertion.client_data,
        &assertion.client_data_json,
        &assertion.authenticator_data,
        &assertion.signature,
        &stored,
    )?;
    if !store::record_use(conn, &credential, asserted).await? {
        return Err(WebauthnError::SignCountRegression.into());
    }
    Ok(Verified {
        credential,
        asserted,
    })
}

/// Verifies a registration answering the user's newest `register`
/// challenge. Storing it is the caller's (transactional) job.
pub async fn verify_registration(
    conn: &impl ConnectionTrait,
    rp: &Rp,
    tenant_id: Uuid,
    user_id: Uuid,
    registration: &Registration,
) -> Result<Registered, PasskeyError> {
    let scope = Scope::User {
        purpose: entity::enums::WebauthnPurpose::Register,
        user_id,
    };
    let consumed =
        challenge::consume(conn, tenant_id, &registration.client_data.challenge, scope).await?;
    if consumed.is_none() {
        return Err(PasskeyError::Challenge);
    }
    Ok(register::verify(
        rp,
        &registration.client_data,
        &registration.attestation_object,
    )?)
}
