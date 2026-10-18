//! Telegram: chats linked to users (sign-in codes and notices), the
//! single-use codes that link them, and the sign-in codes of login
//! transactions.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261014_000008_telegram"
    }
}

// One chat may be linked to several users (one person, many tenants), but a
// user has at most one chat.
// A sign-in code belongs to its login transaction (cascade) and to the user
// the password step identified; one live code per transaction.
const UP: &str = r"
CREATE TABLE telegram_links (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    chat_id bigint NOT NULL,
    username text CHECK (length(username) BETWEEN 1 AND 64),
    linked_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX telegram_links_chat ON telegram_links (chat_id);

CREATE TABLE telegram_link_codes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash bytea NOT NULL UNIQUE CHECK (length(code_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX telegram_link_codes_user ON telegram_link_codes (tenant_id, user_id);
CREATE INDEX telegram_link_codes_expires ON telegram_link_codes (expires_at);

CREATE TABLE telegram_otps (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    tx_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash bytea NOT NULL CHECK (length(code_hash) = 32),
    -- Guesses at the current code; at 5 it is dead.
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    sent_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    UNIQUE (tenant_id, tx_id),
    FOREIGN KEY (tenant_id, tx_id) REFERENCES login_transactions (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX telegram_otps_user ON telegram_otps (tenant_id, user_id);
CREATE INDEX telegram_otps_expires ON telegram_otps (expires_at);
";

const DOWN: &str = r"
DROP TABLE telegram_otps;
DROP TABLE telegram_link_codes;
DROP TABLE telegram_links;
";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(DOWN).await?;
        Ok(())
    }
}
