//! SeaORM entities for the `oauth` identity provider. Schema lives in the
//! `migration` crate; every table except `tenants` carries `tenant_id`.

pub use sea_orm;

pub mod enums;

pub mod app_required_permissions;
pub mod app_role_assignments;
pub mod app_roles;
pub mod app_scopes;
pub mod applications;
pub mod audit_events;
pub mod authorization_codes;
pub mod client_secrets;
pub mod consent_grants;
pub mod directory_role_assignments;
pub mod email_tokens;
pub mod group_members;
pub mod groups;
pub mod known_devices;
pub mod login_transactions;
pub mod notification_prefs;
pub mod opaque_access_tokens;
pub mod outbox;
pub mod rate_limit_buckets;
pub mod refresh_tokens;
pub mod sessions;
pub mod signing_keys;
pub mod tenants;
pub mod user_recovery_codes;
pub mod user_totp;
pub mod users;
pub mod webauthn_challenges;
pub mod webauthn_credentials;

#[cfg(test)]
mod tests {
    use sea_orm::prelude::{DateTimeWithTimeZone, Uuid};

    use super::*;

    fn now() -> DateTimeWithTimeZone {
        DateTimeWithTimeZone::default()
    }

    #[test]
    fn debug_redacts_secret_material() {
        let secret = "s3cr3t-material";
        let bytes = secret.as_bytes().to_vec();
        let id = Uuid::nil();
        let rendered = [
            format!(
                "{:?}",
                users::Model {
                    id,
                    tenant_id: id,
                    user_type: enums::UserType::Member,
                    email: "a@b.c".into(),
                    email_verified: false,
                    display_name: "A".into(),
                    password_hash: Some(secret.into()),
                    must_change_password: false,
                    disabled: false,
                    first_device_at: None,
                    webauthn_handle: Some(bytes.clone()),
                    created_at: now(),
                    updated_at: now(),
                }
            ),
            format!(
                "{:?}",
                user_totp::Model {
                    user_id: id,
                    tenant_id: id,
                    secret_enc: bytes.clone(),
                    created_at: now(),
                    confirmed_at: None,
                    last_used_step: None,
                }
            ),
            format!(
                "{:?}",
                user_recovery_codes::Model {
                    id,
                    tenant_id: id,
                    user_id: id,
                    code_hash: bytes.clone(),
                    used_at: None,
                    created_at: now(),
                }
            ),
            format!(
                "{:?}",
                client_secrets::Model {
                    id,
                    tenant_id: id,
                    application_id: id,
                    secret_hash: bytes.clone(),
                    hint: "abc".into(),
                    description: None,
                    expires_at: None,
                    created_at: now(),
                }
            ),
            format!(
                "{:?}",
                signing_keys::Model {
                    id,
                    tenant_id: id,
                    kid: "k".into(),
                    alg: enums::SigningAlg::Es256,
                    status: enums::KeyStatus::Active,
                    private_key_enc: bytes.clone(),
                    public_jwk: sea_orm::prelude::Json::Null,
                    created_at: now(),
                    activated_at: None,
                    retired_at: None,
                    expires_at: None,
                }
            ),
            format!(
                "{:?}",
                outbox::Model {
                    id,
                    tenant_id: id,
                    channel: enums::Channel::Email,
                    recipient: "a@b.c".into(),
                    kind: "reset".into(),
                    subject: "s".into(),
                    body_enc: Some(bytes.clone()),
                    attempts: 0,
                    next_attempt_at: now(),
                    last_error: None,
                    sent_at: None,
                    dead_at: None,
                    created_at: now(),
                    expires_at: now(),
                }
            ),
            format!(
                "{:?}",
                email_tokens::Model {
                    id,
                    tenant_id: id,
                    user_id: id,
                    token_hash: bytes.clone(),
                    purpose: enums::EmailTokenPurpose::Reset,
                    email: "a@b.c".into(),
                    new_email: None,
                    expires_at: now(),
                    consumed_at: None,
                    created_at: now(),
                }
            ),
            format!(
                "{:?}",
                known_devices::Model {
                    id,
                    tenant_id: id,
                    user_id: id,
                    device_hash: bytes.clone(),
                    user_agent: None,
                    first_seen: now(),
                    last_seen: now(),
                    expires_at: now(),
                }
            ),
            format!(
                "{:?}",
                webauthn_challenges::Model {
                    id,
                    tenant_id: id,
                    challenge_hash: bytes.clone(),
                    purpose: enums::WebauthnPurpose::Login,
                    user_id: None,
                    tx_id: Some(id),
                    created_at: now(),
                    expires_at: now(),
                }
            ),
        ];
        let byte_list = format!("{bytes:?}");
        for text in rendered {
            assert!(text.contains("<redacted>"), "{text}");
            assert!(
                !text.contains(secret) && !text.contains(&byte_list),
                "{text}"
            );
        }
    }
}
