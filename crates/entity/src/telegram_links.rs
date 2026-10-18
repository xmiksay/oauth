//! `telegram_links` table: the Telegram chat linked to a user.

use sea_orm::entity::prelude::*;

// Debug is hand-written so chat ids (personal identifiers) stay out of logs.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "telegram_links")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// The private chat with the bot (= the Telegram user id).
    pub chat_id: i64,
    /// Telegram @username (without `@`) at link time, if the account has one.
    pub username: Option<String>,
    pub linked_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("chat_id", &"<redacted>")
            .field("username", &"<redacted>")
            .field("linked_at", &self.linked_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
