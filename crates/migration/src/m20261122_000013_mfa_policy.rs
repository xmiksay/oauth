//! MFA enforcement: the tenant's `mfa_policy` (`optional` / `required`),
//! each app's override (`inherit` / `required`: an app can only tighten),
//! and the `mfa_enroll` login stage (a user without a second factor sets
//! one up before the code is issued). `login_transactions.step_up` marks a
//! transaction that continues an existing session's sign-in with a second
//! factor: `session_id` then names that session, which must still be live
//! when the step-up completes (and is replaced by a new session).

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000013_mfa_policy"
    }
}

const UP: &str = r"
ALTER TABLE tenants ADD COLUMN mfa_policy text NOT NULL DEFAULT 'optional'
    CONSTRAINT tenants_mfa_policy_check CHECK (mfa_policy IN ('optional', 'required'));
ALTER TABLE applications ADD COLUMN mfa_policy text NOT NULL DEFAULT 'inherit'
    CONSTRAINT applications_mfa_policy_check CHECK (mfa_policy IN ('inherit', 'required'));
ALTER TABLE login_transactions DROP CONSTRAINT login_transactions_stage_check;
ALTER TABLE login_transactions ADD CONSTRAINT login_transactions_stage_check
    CHECK (stage IN ('password', 'mfa', 'change_password', 'consent', 'link', 'mfa_enroll'));
ALTER TABLE login_transactions ADD COLUMN step_up boolean NOT NULL DEFAULT false;
";

const DOWN: &str = r"
DELETE FROM login_transactions WHERE stage = 'mfa_enroll' OR step_up;
ALTER TABLE login_transactions DROP COLUMN step_up;
ALTER TABLE login_transactions DROP CONSTRAINT login_transactions_stage_check;
ALTER TABLE login_transactions ADD CONSTRAINT login_transactions_stage_check
    CHECK (stage IN ('password', 'mfa', 'change_password', 'consent', 'link'));
ALTER TABLE applications DROP COLUMN mfa_policy;
ALTER TABLE tenants DROP COLUMN mfa_policy;
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
