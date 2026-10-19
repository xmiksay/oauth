//! `user_identities` table: upstream identities (IdP + subject) linked to
//! users.

use sea_orm::entity::prelude::*;

// Debug is hand-written: subject and email identify a person upstream and
// have no business in logs.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_identities")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub idp_id: Uuid,
    /// The upstream `sub`.
    pub subject: String,
    /// The upstream email when last seen (informational, never used to
    /// match accounts).
    pub email: Option<String>,
    pub linked_at: DateTimeWithTimeZone,
    pub last_used_at: Option<DateTimeWithTimeZone>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("idp_id", &self.idp_id)
            .field("subject", &"<redacted>")
            .field("email", &"<redacted>")
            .field("linked_at", &self.linked_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
