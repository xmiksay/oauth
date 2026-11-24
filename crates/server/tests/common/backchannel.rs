//! Back-Channel Logout helpers: the web app's logout URI, queued rows and
//! the RP-initiated logout URL.

use entity::{applications, enums::Channel, outbox};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};

use super::flow::Fixture;

pub async fn set_uri(f: &Fixture, uri: Option<&str>) {
    let mut row: applications::ActiveModel = f.web.clone().into();
    row.backchannel_logout_uri = Set(uri.map(str::to_owned));
    row.update(&f.db).await.unwrap();
}

pub async fn queued(f: &Fixture) -> Vec<outbox::Model> {
    outbox::Entity::find()
        .filter(outbox::Column::Channel.eq(Channel::Backchannel))
        .all(&f.db)
        .await
        .unwrap()
}

pub fn logout_url(id_token: &str) -> String {
    let q = form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", id_token)
        .finish();
    format!("/oauth2/logout?{q}")
}

/// Waits until some other backend of this test's database is blocked on a
/// lock — the interleaving a race test sets up — instead of sleeping and
/// hoping. Panics after a generous deadline.
pub async fn wait_for_lock_waiter(db: &sea_orm::DatabaseConnection) {
    wait_for_lock_waiters(db, 1).await;
}

/// [`wait_for_lock_waiter`] until at least `n` backends wait on a lock.
pub async fn wait_for_lock_waiters(db: &sea_orm::DatabaseConnection, n: i64) {
    use sea_orm::{ConnectionTrait, Statement};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let row = db
            .query_one_raw(Statement::from_string(
                db.get_database_backend(),
                "SELECT count(*) AS n FROM pg_stat_activity \
                 WHERE datname = current_database() AND pid <> pg_backend_pid() \
                 AND wait_event_type = 'Lock'",
            ))
            .await
            .unwrap()
            .unwrap();
        if row.try_get::<i64>("", "n").unwrap() >= n {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "nobody blocked on a lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
