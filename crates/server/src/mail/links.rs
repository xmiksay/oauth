//! Issuing an email link: token + rendered message + outbox row, all on the
//! caller's transaction.

use anyhow::bail;
use entity::{enums::Channel, enums::EmailTokenPurpose, tenants, users};
use sea_orm::ConnectionTrait;

use super::{
    outbox::{self, NewMessage},
    templates::{self, Ctx},
    tokens,
};
use crate::config::Config;

/// The SPA page a link of `purpose` opens (on the tenant's host).
pub fn page(purpose: EmailTokenPurpose) -> &'static str {
    match purpose {
        EmailTokenPurpose::Verify | EmailTokenPurpose::Change => "/myaccount/verify-email",
        EmailTokenPurpose::Reset => "/login/reset",
        EmailTokenPurpose::Invite => "/login/invite",
    }
}

/// Sends `user` a `purpose` link: to `new_email` for a change, else to
/// their current address. Earlier links of that purpose stop working.
pub async fn send(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant: &tenants::Model,
    user: &users::Model,
    purpose: EmailTokenPurpose,
    new_email: Option<&str>,
) -> anyhow::Result<()> {
    if !config.email_enabled() {
        bail!("email link requested without SMTP configured");
    }
    let token = tokens::issue(conn, user, purpose, new_email).await?;
    // In the fragment: browsers never send it, so no proxy or access log on
    // the way to the SPA page sees the token.
    let link = format!(
        "{}{}#token={token}",
        config.tenant_origin(&tenant.slug),
        page(purpose)
    );
    let ttl = tokens::ttl(purpose);
    let ctx = Ctx {
        tenant_name: &tenant.display_name,
        user_name: &user.display_name,
        user_email: &user.email,
    };
    let rendered = templates::link_message(&ctx, purpose, &link, ttl, new_email);
    outbox::enqueue(
        conn,
        &config.master_key,
        NewMessage {
            tenant_id: tenant.id,
            channel: Channel::Email,
            recipient: new_email.unwrap_or(&user.email),
            rendered: &rendered,
            ttl,
        },
    )
    .await
}
