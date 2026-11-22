//! Delivery of `backchannel` outbox rows: sign a fresh logout token for the
//! row's application and POST it (`application/x-www-form-urlencoded`,
//! `logout_token=…`) to the app's current `backchannel_logout_uri`.
//!
//! Outbound requests follow the federation client's rules: no redirects,
//! no proxy, timeouts, URLs through `federation::urls` and — outside
//! development — public destinations only (`federation::resolve::PublicOnly`).
//! Never logged: the token, the URL, a reqwest error's text.

use std::{sync::Arc, time::Duration};

use entity::{applications, enums::Channel, outbox, tenants};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use uuid::Uuid;

use super::{Payload, token};
use crate::{
    config::Config,
    federation::{resolve, urls},
    http,
    jobs::outbox::{Courier, open_body},
    mail::MailError,
    tokens::jwt,
};

/// One RP endpoint must answer quickly; the outbox retries later.
const TIMEOUTS: http::Timeouts = http::Timeouts {
    total: Duration::from_secs(10),
    connect: Duration::from_secs(5),
};

/// The back-channel courier: one hardened HTTP client.
pub struct Notifier {
    http: reqwest::Client,
    allow_http_loopback: bool,
}

impl Notifier {
    /// `allow_http_loopback` (development and tests) permits plain-http
    /// loopback endpoints and skips the public-address resolver.
    pub fn new(allow_http_loopback: bool) -> anyhow::Result<Self> {
        let resolver = (!allow_http_loopback)
            .then(|| Arc::new(resolve::PublicOnly) as Arc<dyn reqwest::dns::Resolve>);
        Ok(Self {
            http: http::client(TIMEOUTS, !allow_http_loopback, resolver)?,
            allow_http_loopback,
        })
    }
}

/// How the RP's answer is recorded: 2xx delivered; 5xx / 408 / 429 worth
/// a retry; any other status (the RP refused the token) final.
pub fn outcome(status: u16) -> Result<(), MailError> {
    match status {
        200..=299 => Ok(()),
        408 | 429 | 500..=599 => Err(MailError::Transient),
        _ => Err(MailError::Permanent),
    }
}

fn transient(row: &outbox::Model, what: &'static str) -> impl FnOnce(anyhow::Error) -> MailError {
    let id = row.id;
    move |err| {
        tracing::warn!(message_id = %id, error = ?err, what, "back-channel logout failed");
        MailError::Transient
    }
}

impl Courier for Notifier {
    const CHANNEL: Channel = Channel::Backchannel;

    /// A disabled tenant, a deleted app or one without a (valid) URI is
    /// permanent: the row is dead, never retried.
    async fn deliver(
        &self,
        db: &DatabaseConnection,
        config: &Config,
        row: &outbox::Model,
        tenants: &[tenants::Model],
    ) -> Result<(), MailError> {
        let tenant = tenants
            .iter()
            .find(|t| t.id == row.tenant_id && !t.disabled)
            .ok_or(MailError::Permanent)?;
        let payload: Payload =
            serde_json::from_str(&open_body(config, row)?).map_err(|_| MailError::Permanent)?;
        let app_id = Uuid::parse_str(&row.recipient).map_err(|_| MailError::Permanent)?;
        let app = applications::Entity::find_by_id(app_id)
            .filter(applications::Column::TenantId.eq(row.tenant_id))
            .one(db)
            .await
            .map_err(|err| transient(row, "loading application")(err.into()))?
            .ok_or(MailError::Permanent)?;
        let url = app
            .backchannel_logout_uri
            .as_deref()
            .and_then(|uri| urls::checked(uri, self.allow_http_loopback))
            .ok_or(MailError::Permanent)?;
        let issuer = config.issuer(&tenant.slug);
        let claims = token::claims(&token::Input {
            issuer: &issuer,
            client_id: &app.client_id,
            sid: payload.sid,
            sub: payload.sub,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
        });
        let logout_token = jwt::sign(
            db,
            &config.master_key,
            tenant.id,
            app.signing_alg,
            token::TYP,
            &claims,
        )
        .await
        .map_err(transient(row, "signing logout token"))?;
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", &logout_token)
            .finish();
        let response = self
            .http
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(|err| {
                tracing::warn!(
                    message_id = %row.id, timeout = err.is_timeout(), connect = err.is_connect(),
                    "back-channel logout endpoint unreachable"
                );
                MailError::Transient
            })?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            tracing::warn!(message_id = %row.id, status, "back-channel logout refused");
        }
        outcome(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_outcomes() {
        assert_eq!(outcome(200), Ok(()));
        assert_eq!(outcome(204), Ok(()));
        for retry in [408, 429, 500, 503] {
            assert_eq!(outcome(retry), Err(MailError::Transient), "{retry}");
        }
        for refused in [301, 400, 401, 404] {
            assert_eq!(outcome(refused), Err(MailError::Permanent), "{refused}");
        }
    }

    #[test]
    fn builds_both_variants() {
        assert!(Notifier::new(true).is_ok());
        assert!(Notifier::new(false).is_ok());
    }
}
