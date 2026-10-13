//! Client authentication at the back-channel endpoints (RFC 6749 §2.3):
//! `client_secret_basic` / `client_secret_post` for confidential clients,
//! `client_id` alone for public clients. Exactly one method per request.

use std::collections::HashMap;

use anyhow::Context;
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use entity::{applications, client_secrets, enums::ClientType};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use super::error::{ErrorCode, OAuthError, OAuthResult};
use crate::secret;

/// RFC 6749 §2.3.1: Basic credentials are form-urlencoded before base64.
fn form_decode(raw: &str) -> Option<String> {
    let spaced = raw.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// `Ok(None)` = no Basic header; `Err(())` = a malformed one.
fn parse_basic(headers: &HeaderMap) -> Result<Option<(String, String)>, ()> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Err(());
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let decoded = STANDARD.decode(encoded.trim()).map_err(|_| ())?;
    let decoded = String::from_utf8(decoded).map_err(|_| ())?;
    let (id, secret) = decoded.split_once(':').ok_or(())?;
    Ok(Some((
        form_decode(id).ok_or(())?,
        form_decode(secret).ok_or(())?,
    )))
}

fn invalid_client(basic: bool, description: &str) -> OAuthError {
    let mut err = OAuthError::new(ErrorCode::InvalidClient, description);
    err.basic_challenge = basic;
    err
}

pub async fn find_client(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    client_id: &str,
) -> anyhow::Result<Option<applications::Model>> {
    applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant_id))
        .filter(applications::Column::ClientId.eq(client_id))
        .one(conn)
        .await
        .context("looking up client")
}

/// True if `candidate` matches an unexpired secret of the app. Every stored
/// hash is compared (constant time each) so timing reveals nothing.
async fn secret_matches(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    app_id: Uuid,
    candidate: &str,
) -> anyhow::Result<bool> {
    let now = chrono::Utc::now().fixed_offset();
    let wanted = secret::hash(candidate);
    let rows = client_secrets::Entity::find()
        .filter(client_secrets::Column::TenantId.eq(tenant_id))
        .filter(client_secrets::Column::ApplicationId.eq(app_id))
        .all(conn)
        .await
        .context("loading client secrets")?;
    Ok(rows
        .iter()
        .filter(|row| row.expires_at.is_none_or(|exp| exp > now))
        .fold(false, |found, row| {
            secret::ct_eq(&row.secret_hash, &wanted) | found
        }))
}

pub async fn authenticate(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> OAuthResult<applications::Model> {
    let basic =
        parse_basic(headers).map_err(|()| invalid_client(true, "malformed Basic credentials"))?;
    let post_id = params.get("client_id");
    let post_secret = params.get("client_secret");
    let used_basic = basic.is_some();
    let (client_id, presented) = match basic {
        Some((id, secret)) => {
            if post_secret.is_some() || post_id.is_some_and(|p| *p != id) {
                return Err(OAuthError::invalid_request(
                    "use exactly one client authentication method",
                ));
            }
            (id, Some(secret))
        }
        None => match post_id {
            Some(id) => (id.clone(), post_secret.cloned()),
            None => return Err(invalid_client(false, "client authentication required")),
        },
    };
    let app = find_client(conn, tenant_id, &client_id)
        .await?
        .ok_or_else(|| invalid_client(used_basic, "client authentication failed"))?;
    match (app.client_type, presented) {
        (ClientType::Confidential, Some(secret))
            if secret_matches(conn, tenant_id, app.id, &secret).await? =>
        {
            Ok(app)
        }
        (ClientType::Public, None) => Ok(app),
        _ => Err(invalid_client(used_basic, "client authentication failed")),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn basic(raw: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let value = format!("Basic {}", STANDARD.encode(raw));
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        h
    }

    #[test]
    fn parses_basic_credentials_form_decoded() {
        assert_eq!(
            parse_basic(&basic("my%20app:s3cr%3At+x")).unwrap(),
            Some(("my app".into(), "s3cr:t x".into()))
        );
        assert_eq!(parse_basic(&HeaderMap::new()).unwrap(), None);
        assert!(parse_basic(&basic("no-colon")).is_err());
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!"));
        assert!(parse_basic(&h).is_err());
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(parse_basic(&h).unwrap(), None);
    }
}
