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
