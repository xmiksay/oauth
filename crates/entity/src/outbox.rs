//! `outbox` table: messages waiting for (or past) delivery by the outbox job.

use sea_orm::entity::prelude::*;

use crate::enums::Channel;

// Debug is hand-written so the sealed body never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "outbox")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub channel: Channel,
    pub recipient: String,
    pub kind: String,
    pub subject: String,
    /// AES-256-GCM sealed body (it carries link tokens); `None` once the
    /// message was sent or given up.
    pub body_enc: Option<Vec<u8>>,
    pub attempts: i32,
    pub next_attempt_at: DateTimeWithTimeZone,
    /// Error kind of the last failed attempt (never message text).
    pub last_error: Option<String>,
    pub sent_at: Option<DateTimeWithTimeZone>,
    pub dead_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("channel", &self.channel)
            .field("recipient", &self.recipient)
            .field("kind", &self.kind)
            .field("subject", &self.subject)
            .field("body_enc", &"<redacted>")
            .field("attempts", &self.attempts)
            .field("next_attempt_at", &self.next_attempt_at)
            .field("last_error", &self.last_error)
            .field("sent_at", &self.sent_at)
            .field("dead_at", &self.dead_at)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
