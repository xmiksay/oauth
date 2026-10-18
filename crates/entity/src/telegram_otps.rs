//! `telegram_otps` table: the sign-in code sent via Telegram for a login
//! transaction.

use sea_orm::entity::prelude::*;

// Debug is hand-written so the code hash never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "telegram_otps")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub tx_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 over the transaction id and the code.
    pub code_hash: Vec<u8>,
    /// Guesses at the current code (dead at the limit).
    pub attempts: i32,
    pub sent_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("tx_id", &self.tx_id)
            .field("user_id", &self.user_id)
            .field("code_hash", &"<redacted>")
            .field("attempts", &self.attempts)
            .field("sent_at", &self.sent_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
