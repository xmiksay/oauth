//! Tenant resolution from the `{tenant}` path segment (M1a: path-based; M1b
//! adds `Host` / custom domains).

use std::sync::Arc;

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use entity::tenants;

use crate::{
    app::AppState,
    directory::{self, slug},
    error::AppError,
};

/// The active tenant named by the request path. Unknown and disabled tenants
/// are indistinguishable (404). Resolved once per request and cached in the
/// request extensions, so several extractors / handlers share one lookup.
#[derive(Clone, Debug)]
pub struct Tenant(pub Arc<tenants::Model>);

impl std::ops::Deref for Tenant {
    type Target = tenants::Model;

    fn deref(&self) -> &tenants::Model {
        &self.0
    }
}

impl FromRequestParts<AppState> for Tenant {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        if let Some(tenant) = parts.extensions.get::<Tenant>() {
            return Ok(tenant.clone());
        }
        let params = RawPathParams::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::NotFound)?;
        let slug = params
            .iter()
            .find(|(name, _)| *name == "tenant")
            .map(|(_, value)| value)
            .ok_or(AppError::NotFound)?;
        // Cheap shape check first: garbage never reaches the database.
        if slug::validate_format(slug).is_err() {
            return Err(AppError::NotFound);
        }
        let tenant = directory::find_tenant_by_slug(&state.db, slug)
            .await?
            .filter(|t| !t.disabled)
            .ok_or(AppError::NotFound)?;
        let tenant = Tenant(Arc::new(tenant));
        parts.extensions.insert(tenant.clone());
        Ok(tenant)
    }
}
