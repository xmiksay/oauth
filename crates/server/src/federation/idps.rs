//! Lookups of a tenant's identity providers and their sealed secret.

use anyhow::Context;
use entity::identity_providers;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{keys::wrap, oidc::params::AuthRequest};

/// The tenant's IdP `id`, enabled or not.
pub async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> anyhow::Result<Option<identity_providers::Model>> {
    identity_providers::Entity::find_by_id(id)
        .filter(identity_providers::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await
        .context("loading identity provider")
}

/// The IdP row locked `FOR SHARE` until the caller's transaction ends —
/// if it is still enabled and at `generation`. A repoint (`FOR UPDATE`)
/// waits for the caller, or the caller sees the new generation and stops.
pub async fn lock_current(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
    generation: i64,
) -> anyhow::Result<Option<identity_providers::Model>> {
    Ok(identity_providers::Entity::find_by_id(id)
        .filter(identity_providers::Column::TenantId.eq(tenant_id))
        .lock_shared()
        .one(conn)
        .await
        .context("locking identity provider")?
        .filter(|idp| idp.enabled && idp.generation == generation))
}

pub async fn find_enabled(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> anyhow::Result<Option<identity_providers::Model>> {
    Ok(find(conn, tenant_id, id).await?.filter(|idp| idp.enabled))
}

/// The tenant's enabled IdPs, by name.
pub async fn enabled(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
) -> anyhow::Result<Vec<identity_providers::Model>> {
    identity_providers::Entity::find()
        .filter(identity_providers::Column::TenantId.eq(tenant_id))
        .filter(identity_providers::Column::Enabled.eq(true))
        .order_by_asc(identity_providers::Column::Name)
        .all(conn)
        .await
        .context("listing identity providers")
}

/// The lower-cased domain of an email address.
pub fn email_domain(email: &str) -> Option<String> {
    let (_, domain) = email.trim().rsplit_once('@')?;
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

/// The enabled IdP that `domain` (lower-case) belongs to.
pub fn for_domain<'a>(
    idps: &'a [identity_providers::Model],
    domain: &str,
) -> Option<&'a identity_providers::Model> {
    idps.iter()
        .find(|idp| idp.email_domains.iter().any(|d| d == domain))
}

/// The IdP an authorize request asked for: `idp` (an IdP id) first, else
/// the IdP of `domain_hint`.
pub fn hinted<'a>(
    idps: &'a [identity_providers::Model],
    req: &AuthRequest,
) -> Option<&'a identity_providers::Model> {
    if let Some(id) = req.idp.as_deref().and_then(|s| Uuid::parse_str(s).ok())
        && let Some(idp) = idps.iter().find(|idp| idp.id == id)
    {
        return Some(idp);
    }
    let domain = req.domain_hint.as_deref()?.trim().to_ascii_lowercase();
    for_domain(idps, &domain)
}

pub fn seal_secret(
    master_key: &[u8; 32],
    tenant_id: Uuid,
    idp_id: Uuid,
    secret: &str,
) -> anyhow::Result<Vec<u8>> {
    wrap::seal(
        master_key,
        &wrap::idp_aad(tenant_id, idp_id),
        secret.as_bytes(),
    )
}

pub fn client_secret(
    master_key: &[u8; 32],
    idp: &identity_providers::Model,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    let Some(sealed) = &idp.client_secret_sealed else {
        return Ok(None);
    };
    let plain = wrap::open(master_key, &wrap::idp_aad(idp.tenant_id, idp.id), sealed)?;
    let secret = String::from_utf8(plain.to_vec()).context("sealed client secret is not UTF-8")?;
    Ok(Some(Zeroizing::new(secret)))
}

#[cfg(test)]
mod tests {
    use entity::enums::{IdpClientAuth, IdpKind, IdpPolicy};

    use super::*;

    fn idp(domains: &[&str]) -> identity_providers::Model {
        let now = chrono::Utc::now().fixed_offset();
        identity_providers::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            name: "x".into(),
            kind: IdpKind::Oidc,
            enabled: true,
            visible: true,
            issuer: "https://up".into(),
            discovery_url: None,
            client_id: "c".into(),
            client_secret_sealed: None,
            client_auth: IdpClientAuth::Post,
            scopes: vec![],
            policy: IdpPolicy::LinkOnly,
            trust_upstream_mfa: false,
            mfa_acr: None,
            email_domains: domains.iter().map(|d| (*d).to_owned()).collect(),
            generation: 1,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn domains_and_hints() {
        assert_eq!(
            email_domain(" Ann@Contoso.COM ").as_deref(),
            Some("contoso.com")
        );
        assert_eq!(email_domain("a@b@c.example").as_deref(), Some("c.example"));
        assert_eq!(email_domain("nope"), None);
        assert_eq!(email_domain("a@"), None);
        let idps = [idp(&["a.example"]), idp(&["b.example", "c.example"])];
        assert_eq!(
            for_domain(&idps, "c.example").map(|i| i.id),
            Some(idps[1].id)
        );
        assert!(for_domain(&idps, "d.example").is_none());
        let mut req: AuthRequest = serde_json::from_value(serde_json::json!({
            "client_id": "c", "redirect_uri": "https://r", "state": null, "nonce": null,
            "code_challenge": "x", "oidc_scopes": [], "resource_id": null,
            "resource_scopes": [], "prompt": null, "max_age": null,
            "domain_hint": "B.example",
        }))
        .unwrap();
        assert_eq!(hinted(&idps, &req).map(|i| i.id), Some(idps[1].id));
        req.idp = Some(idps[0].id.to_string());
        assert_eq!(hinted(&idps, &req).map(|i| i.id), Some(idps[0].id));
        req.idp = Some(Uuid::now_v7().to_string());
        req.domain_hint = None;
        assert!(hinted(&idps, &req).is_none());
    }

    #[test]
    fn secrets_roundtrip_bound_to_the_idp() {
        let key = [3u8; 32];
        let mut row = idp(&[]);
        row.client_secret_sealed = Some(seal_secret(&key, row.tenant_id, row.id, "s3").unwrap());
        assert_eq!(
            client_secret(&key, &row)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("s3")
        );
        row.id = Uuid::now_v7();
        assert!(client_secret(&key, &row).is_err());
    }
}
