//! `GET /api/v1/tenants/{t}/audit-events` — newest first, filterable.

use axum::extract::State;
use chrono::DateTime;
use entity::audit_events;
use sea_orm::{ActiveEnum, ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::Query,
    page::{self, Order, PageParams, Paged},
    ts,
};
use crate::{
    app::AppState,
    authz::{Access, Area},
    error::{AppError, AppResult},
};

fn view(e: &audit_events::Model) -> Value {
    json!({
        "id": e.id,
        "at": ts(&e.at),
        "actor_type": e.actor_type.to_value(),
        "actor_id": e.actor_id,
        "event_type": e.event_type,
        "target_type": e.target_type,
        "target_id": e.target_id,
        "outcome": e.outcome.to_value(),
        "ip": e.ip,
        "details": e.details,
    })
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    page: PageParams,
    event_type: Option<String>,
    actor_id: Option<Uuid>,
    target_id: Option<Uuid>,
    /// RFC 3339, inclusive.
    from: Option<String>,
    /// RFC 3339, exclusive.
    to: Option<String>,
}

fn timestamp(raw: &str, name: &str) -> AppResult<DateTime<chrono::FixedOffset>> {
    DateTime::parse_from_rfc3339(raw)
        .map_err(|_| AppError::BadRequest(format!("{name} must be an RFC 3339 timestamp")))
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::AuditLog, Access::Read)?;
    let mut select =
        audit_events::Entity::find().filter(audit_events::Column::TenantId.eq(caller.tenant_id()));
    if let Some(kind) = q.event_type.as_deref().filter(|s| !s.is_empty()) {
        select = select.filter(audit_events::Column::EventType.eq(kind));
    }
    if let Some(id) = q.actor_id {
        select = select.filter(audit_events::Column::ActorId.eq(id));
    }
    if let Some(id) = q.target_id {
        select = select.filter(audit_events::Column::TargetId.eq(id));
    }
    if let Some(from) = q.from.as_deref() {
        select = select.filter(audit_events::Column::At.gte(timestamp(from, "from")?));
    }
    if let Some(to) = q.to.as_deref() {
        select = select.filter(audit_events::Column::At.lt(timestamp(to, "to")?));
    }
    let page = page::fetch(
        &state.db,
        select,
        audit_events::Column::Id,
        q.page.parse()?,
        Order::Descending,
        |e| e.id,
    )
    .await?;
    Ok(page.map(|e| view(&e)))
}
