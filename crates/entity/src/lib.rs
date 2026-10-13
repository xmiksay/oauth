//! SeaORM entities for the `oauth` identity provider. Schema lives in the
//! `migration` crate; every table except `tenants` carries `tenant_id`.

pub use sea_orm;

pub mod enums;

pub mod app_required_permissions;
pub mod app_role_assignments;
pub mod app_roles;
pub mod app_scopes;
pub mod applications;
pub mod client_secrets;
pub mod consent_grants;
pub mod directory_role_assignments;
pub mod group_members;
pub mod groups;
pub mod signing_keys;
pub mod tenants;
pub mod user_recovery_codes;
pub mod user_totp;
pub mod users;

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
