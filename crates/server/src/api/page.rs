//! Keyset pagination over UUIDv7 primary keys (`?limit=&cursor=`). UUIDv7
//! sort in creation order, so "after the last id seen" is a stable cursor
//! even while rows are inserted. Lists are oldest first; the audit log is
//! newest first.

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Select,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

pub const DEFAULT_LIMIT: u64 = 50;
pub const MAX_LIMIT: u64 = 200;

/// Raw query parameters. Strings, because `serde(flatten)` (how list
/// endpoints embed this) can only hand string values to the deserializer.
#[derive(Debug, Default, Deserialize)]
pub struct PageParams {
    pub limit: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub limit: u64,
    /// The last id of the previous page.
    pub after: Option<Uuid>,
}

impl PageParams {
    pub fn parse(&self) -> AppResult<Page> {
        let limit = match self.limit.as_deref() {
            None | Some("") => DEFAULT_LIMIT,
            Some(raw) => raw
                .parse::<u64>()
                .ok()
                .filter(|n| (1..=MAX_LIMIT).contains(n))
                .ok_or_else(|| AppError::BadRequest(format!("limit must be 1-{MAX_LIMIT}")))?,
        };
        let after = match self.cursor.as_deref() {
            None | Some("") => None,
            Some(raw) => Some(
                Uuid::parse_str(raw).map_err(|_| AppError::BadRequest("invalid cursor".into()))?,
            ),
        };
        Ok(Page { limit, after })
    }
}

/// One page of a list response.
#[derive(Debug, Serialize)]
pub struct Paged<T> {
    pub items: Vec<T>,
    /// Pass as `cursor` for the next page; `null` on the last page.
    pub next_cursor: Option<String>,
}

impl<T: Serialize> IntoResponse for Paged<T> {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

impl<T> Paged<T> {
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Paged<U> {
        Paged {
            items: self.items.into_iter().map(f).collect(),
            next_cursor: self.next_cursor,
        }
    }
}

/// Trims the extra row fetched to detect a next page.
pub fn finish<T>(mut rows: Vec<T>, page: Page, id_of: impl Fn(&T) -> Uuid) -> Paged<T> {
    let limit = usize::try_from(page.limit).unwrap_or(usize::MAX);
    let next_cursor = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|row| id_of(row).to_string())
    } else {
        None
    };
    Paged {
        items: rows,
        next_cursor,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    Ascending,
    /// Newest first.
    Descending,
}

/// Runs `select` keyset-paginated on the UUIDv7 column `id`.
pub async fn fetch<E: EntityTrait>(
    conn: &impl ConnectionTrait,
    select: Select<E>,
    id: E::Column,
    page: Page,
    order: Order,
    id_of: impl Fn(&E::Model) -> Uuid,
) -> AppResult<Paged<E::Model>> {
    let mut select = select;
    select = match (order, page.after) {
        (Order::Ascending, Some(after)) => select.filter(id.gt(after)),
        (Order::Descending, Some(after)) => select.filter(id.lt(after)),
        (_, None) => select,
    };
    select = match order {
        Order::Ascending => select.order_by_asc(id),
        Order::Descending => select.order_by_desc(id),
    };
    let rows = select.limit(page.limit + 1).all(conn).await?;
    Ok(finish(rows, page, id_of))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(limit: Option<&str>, cursor: Option<&str>) -> PageParams {
        PageParams {
            limit: limit.map(str::to_owned),
            cursor: cursor.map(str::to_owned),
        }
    }

    #[test]
    fn parses_limit_and_cursor() {
        assert_eq!(
            params(None, None).parse().unwrap(),
            Page {
                limit: DEFAULT_LIMIT,
                after: None
            }
        );
        let id = Uuid::now_v7();
        let page = params(Some("10"), Some(&id.to_string())).parse().unwrap();
        assert_eq!(
            page,
            Page {
                limit: 10,
                after: Some(id)
            }
        );
        assert_eq!(params(Some("200"), Some("")).parse().unwrap().limit, 200);
        for bad in ["0", "201", "-1", "ten"] {
            assert!(params(Some(bad), None).parse().is_err(), "{bad}");
        }
        assert!(params(None, Some("not-a-uuid")).parse().is_err());
    }

    #[test]
    fn next_cursor_only_when_more_rows_exist() {
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::now_v7()).collect();
        let page = |limit| Page { limit, after: None };
        let full = finish(ids.clone(), page(2), |id| *id);
        assert_eq!(full.items, ids[..2]);
        assert_eq!(full.next_cursor, Some(ids[1].to_string()));
        let last = finish(ids.clone(), page(3), |id| *id);
        assert_eq!(last.items.len(), 3);
        assert_eq!(last.next_cursor, None);
        assert_eq!(
            finish(Vec::<Uuid>::new(), page(5), |id| *id).next_cursor,
            None
        );
    }

    #[test]
    fn uuid_v7_cursors_order_by_creation() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert!(a < b, "keyset pagination relies on v7 ordering");
    }
}
