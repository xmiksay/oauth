//! Closed value sets. Stored as `text` with a matching `CHECK` constraint (see
//! the migration crate docs for why not Postgres enum types).

use sea_orm::entity::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum UserType {
    #[sea_orm(string_value = "member")]
    Member,
    #[sea_orm(string_value = "guest")]
    Guest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum DirectoryRole {
    #[sea_orm(string_value = "GlobalAdmin")]
    GlobalAdmin,
    #[sea_orm(string_value = "ApplicationAdmin")]
    ApplicationAdmin,
    #[sea_orm(string_value = "UserAdmin")]
    UserAdmin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ClientType {
    #[sea_orm(string_value = "confidential")]
    Confidential,
    #[sea_orm(string_value = "public")]
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum AccessTokenFormat {
    #[sea_orm(string_value = "jwt")]
    Jwt,
    #[sea_orm(string_value = "opaque")]
    Opaque,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum SigningAlg {
    #[sea_orm(string_value = "RS256")]
    Rs256,
    #[sea_orm(string_value = "ES256")]
    Es256,
}

impl SigningAlg {
    /// JOSE `alg` name (RFC 7518).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum KeyStatus {
    /// Published in JWKS, not yet signing.
    #[sea_orm(string_value = "next")]
    Next,
    #[sea_orm(string_value = "active")]
    Active,
    /// No longer signing; published until `expires_at`.
    #[sea_orm(string_value = "retired")]
    Retired,
}

/// Values of `app_roles.allowed_member_types` (a `text[]` with a matching
/// DB CHECK).
pub mod member_type {
    pub const USER: &str = "user";
    pub const APPLICATION: &str = "application";
}

/// Who performed an audited action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ActorType {
    #[sea_orm(string_value = "user")]
    User,
    #[sea_orm(string_value = "application")]
    Application,
    #[sea_orm(string_value = "system")]
    System,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum Outcome {
    #[sea_orm(string_value = "success")]
    Success,
    #[sea_orm(string_value = "failure")]
    Failure,
}

/// Delivery channel of an outbox message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum Channel {
    #[sea_orm(string_value = "email")]
    Email,
    #[sea_orm(string_value = "telegram")]
    Telegram,
}

/// What an email link token proves / allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum EmailTokenPurpose {
    /// Verifies the user's current address.
    #[sea_orm(string_value = "verify")]
    Verify,
    #[sea_orm(string_value = "reset")]
    Reset,
    #[sea_orm(string_value = "invite")]
    Invite,
    /// Verifies `new_email` and makes it the user's address.
    #[sea_orm(string_value = "change")]
    Change,
}

/// Security notices a user can opt out of, per channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum NotifyEvent {
    #[sea_orm(string_value = "password_changed")]
    PasswordChanged,
    #[sea_orm(string_value = "mfa_changed")]
    MfaChanged,
    #[sea_orm(string_value = "email_changed")]
    EmailChanged,
    #[sea_orm(string_value = "new_sign_in")]
    NewSignIn,
    #[sea_orm(string_value = "token_reuse")]
    TokenReuse,
    #[sea_orm(string_value = "identity_linked")]
    IdentityLinked,
}

/// Next step of a login transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum LoginStage {
    #[sea_orm(string_value = "password")]
    Password,
    /// Second factor: TOTP or a recovery code.
    #[sea_orm(string_value = "mfa")]
    Mfa,
    #[sea_orm(string_value = "change_password")]
    ChangePassword,
    #[sea_orm(string_value = "consent")]
    Consent,
    /// An unknown upstream identity waits (`pending_identity`) for the user
    /// to sign in locally, which links it.
    #[sea_orm(string_value = "link")]
    Link,
}

impl LoginStage {
    /// Wire name used by the login JSON API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Mfa => "mfa",
            Self::ChangePassword => "change_password",
            Self::Consent => "consent",
            Self::Link => "link",
        }
    }
}

/// What a WebAuthn challenge may be answered for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum WebauthnPurpose {
    /// Creating a credential (My Account, invitation).
    #[sea_orm(string_value = "register")]
    Register,
    /// An assertion in a login transaction.
    #[sea_orm(string_value = "login")]
    Login,
    /// An assertion re-authenticating a signed-in user (My Account).
    #[sea_orm(string_value = "reauth")]
    Reauth,
}

/// Protocol of an upstream identity provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum IdpKind {
    #[sea_orm(string_value = "oidc")]
    Oidc,
}

/// How we authenticate to an upstream token endpoint (RFC 6749 §2.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum IdpClientAuth {
    #[sea_orm(string_value = "post")]
    Post,
    #[sea_orm(string_value = "basic")]
    Basic,
}

/// What a first sign-in with an unknown upstream identity does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum IdpPolicy {
    /// Create the user just in time (verified email, never an existing one).
    #[sea_orm(string_value = "jit")]
    Jit,
    /// Sign in with an existing account once to link it.
    #[sea_orm(string_value = "link_only")]
    LinkOnly,
    #[sea_orm(string_value = "deny")]
    Deny,
}

/// What an upstream round trip is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum FederationPurpose {
    /// Signing in within a login transaction.
    #[sea_orm(string_value = "login")]
    Login,
    /// A signed-in user linking an identity from My Account.
    #[sea_orm(string_value = "link")]
    Link,
}
