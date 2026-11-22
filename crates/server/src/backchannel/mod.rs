//! OpenID Connect Back-Channel Logout 1.0 (OP side).
//!
//! Every user-token issuance records its client in `session_clients`
//! ([`record_client`]). When sessions end — RP-initiated logout, a device
//! signed out in My Account, "sign out everywhere", an admin revoking a
//! user's sessions, password changes / resets, disabling or deleting a
//! user, a new sign-in replacing the browser's session — [`queue`] (called BEFORE the sessions
//! are deleted, on the same transaction) puts one `backchannel` outbox row
//! per (session, client with a `backchannel_logout_uri`). `deliver` signs a
//! fresh logout token per attempt and POSTs it. Sessions that simply expire
//! notify nobody.

pub mod deliver;
pub mod token;

use anyhow::Context;
use chrono::Duration;
use entity::enums::Channel;
use sea_orm::{ConnectionTrait, Statement};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::mail::{
    outbox::{self, NewMessage},
    templates::Rendered,
};

/// `outbox.kind` of logout token deliveries.
pub const KIND: &str = "backchannel_logout";
/// Undelivered after this long, a notification is dropped (the RP's own
/// session has long been due for re-validation by then).
const TTL_HOURS: i64 = 24;

/// What the outbox row carries (sealed like every outbox body).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub sid: Uuid,
    pub sub: Uuid,
}

/// Which sessions are about to end.
#[derive(Clone, Copy, Debug)]
pub enum Ended {
    Session(Uuid),
    /// Every session of the user except `keep`.
    User {
        user_id: Uuid,
        keep: Option<Uuid>,
    },
}

/// The first lock of anything that then locks one of the user's sessions or
/// inserts rows referencing the user (their FK takes this same key lock, but
/// too late): the user row `FOR KEY SHARE`. Admin revocation / disabling /
/// deletion / password resets hold it `FOR UPDATE` while they lock the
/// sessions, so taking a session first deadlocks against them. Global order:
/// IdP → user → session → tokens. Its own statement: the order of row locks
/// within one statement isn't guaranteed.
pub async fn lock_user(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<()> {
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        "SELECT 1 FROM users WHERE tenant_id = $1 AND id = $2 FOR KEY SHARE",
        [tenant_id.into(), user_id.into()],
    ))
    .await
    .context("locking the user")?;
    Ok(())
}

/// Remembers that `application_id` obtained tokens in `session_id` and
/// returns whether the session still exists (`false`: nothing recorded,
/// e.g. a refresh after the session ended).
///
/// Lock order, held to the end of the caller's transaction: the user row
/// `FOR KEY SHARE`, then the session `FOR KEY SHARE`, then (the caller) the
/// tokens. It is the one order every path takes: admin revocation / disable
/// / password reset lock the user `FOR UPDATE` and then the sessions
/// ([`queue`]), logout locks the session then its tokens, and token inserts
/// would otherwise take the user's key lock (FK) only after the session's —
/// a cycle with the admin paths. So a logout or revocation racing the
/// caller either waits for it (and then notifies this client and revokes the
/// tokens it issued) or ends first (the locked read then skips the deleted
/// session: nothing is inserted, no FK violation). Call it BEFORE inserting
/// tokens bound to the session.
pub async fn record_client(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
    application_id: Uuid,
) -> anyhow::Result<bool> {
    lock_user(conn, tenant_id, user_id).await?;
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "WITH s AS (SELECT tenant_id, id FROM sessions \
               WHERE tenant_id = $1 AND id = $2 AND user_id = $4 FOR KEY SHARE), \
             ins AS (INSERT INTO session_clients (tenant_id, session_id, application_id) \
               SELECT tenant_id, id, $3 FROM s ON CONFLICT DO NOTHING) \
             SELECT EXISTS (SELECT 1 FROM s) AS live",
            [
                tenant_id.into(),
                session_id.into(),
                application_id.into(),
                user_id.into(),
            ],
        ))
        .await
        .context("recording the session's client")?
        .context("recording the session's client returned no row")?;
    row.try_get::<bool>("", "live")
        .context("reading whether the session is live")
}

/// Queues a logout notification for every client with a back-channel URI
/// that obtained tokens in the `ended` sessions. Call it on the transaction
/// that deletes them, before the delete (their `session_clients` cascade).
///
/// The ended sessions are locked `FOR UPDATE` first, in id order (two
/// revocations of one user's sessions — My Account's doesn't lock the user —
/// must not take them in opposite orders), so a concurrent
/// [`record_client`] either committed before (and its row is read below,
/// in a fresh read-committed snapshot) or waits until they are gone.
pub async fn queue(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    tenant_id: Uuid,
    ended: Ended,
) -> anyhow::Result<()> {
    let (session, user, keep) = match ended {
        Ended::Session(id) => (Some(id), None, None),
        Ended::User { user_id, keep } => (None, Some(user_id), keep),
    };
    let filter = [tenant_id.into(), session.into(), user.into(), keep.into()];
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        "SELECT id FROM sessions s WHERE s.tenant_id = $1 \
         AND ($2::uuid IS NULL OR s.id = $2) \
         AND ($3::uuid IS NULL OR s.user_id = $3) \
         AND ($4::uuid IS NULL OR s.id <> $4) ORDER BY s.id FOR UPDATE",
        filter.clone(),
    ))
    .await
    .context("locking the ended sessions")?;
    let rows = conn
        .query_all_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT sc.session_id, s.user_id, sc.application_id FROM session_clients sc \
             JOIN sessions s ON s.tenant_id = sc.tenant_id AND s.id = sc.session_id \
             JOIN applications a ON a.tenant_id = sc.tenant_id AND a.id = sc.application_id \
             WHERE sc.tenant_id = $1 AND a.backchannel_logout_uri IS NOT NULL \
             AND ($2::uuid IS NULL OR s.id = $2) \
             AND ($3::uuid IS NULL OR s.user_id = $3) \
             AND ($4::uuid IS NULL OR s.id <> $4)",
            filter,
        ))
        .await
        .context("finding back-channel logout recipients")?;
    for row in rows {
        let read = |col: &str| row.try_get::<Uuid>("", col);
        let payload = Payload {
            sid: read("session_id").context("reading session id")?,
            sub: read("user_id").context("reading user id")?,
        };
        let app_id = read("application_id").context("reading application id")?;
        let rendered = Rendered {
            kind: KIND.to_owned(),
            subject: "Back-channel logout".to_owned(),
            body: Zeroizing::new(serde_json::to_string(&payload)?),
        };
        let msg = NewMessage {
            tenant_id,
            channel: Channel::Backchannel,
            recipient: &app_id.to_string(),
            rendered: &rendered,
            ttl: Duration::hours(TTL_HOURS),
        };
        outbox::enqueue(conn, master_key, msg).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips() {
        let p = Payload {
            sid: Uuid::now_v7(),
            sub: Uuid::now_v7(),
        };
        let text = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Payload>(&text).unwrap(), p);
    }
}
