//! Serves the built Vue SPA (`web/dist`) on tenant hosts (the host gate in
//! `app.rs` keeps it off the apex unless `APEX_TENANT` puts a tenant there).
//! `/` (the portal / dashboard) and client-side routes under
//! `/login|logout|device|myaccount|admin` fall back to `index.html` (as does
//! `/index.html` itself, so every HTML entry point carries the tenant meta);
//! anything else is looked up as a static asset.

use std::{path::Path, sync::Arc};

use axum::{
    Router,
    extract::Request,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use tower_http::services::ServeDir;

use crate::tenancy::Tenant;

/// `logout` is the sign-out confirmation page (`oidc::logout`), `device` the
/// device-code verification page (`verification_uri`).
const SPA_AREAS: [&str; 5] = ["login", "logout", "device", "myaccount", "admin"];

/// Name of the `<meta>` carrying the tenant's slug. WHY: the SPA can't tell
/// the tenant from the host name alone — on the apex (`APEX_TENANT`) the
/// first label is not a slug.
pub const TENANT_META: &str = "oauth-tenant";

pub fn router<S: Clone + Send + Sync + 'static>(dist: &Path) -> Router<S> {
    let index: Arc<Path> = dist.join("index.html").into();
    if !index.is_file() {
        // Not fatal: the API stays usable without a frontend build (e.g. in
        // backend-only dev); SPA paths just answer 404.
        tracing::warn!(dir = %dist.display(), "SPA build not found; frontend routes will 404");
    }
    let page = get(move |req: Request| index_page(index.clone(), req));
    let mut router = Router::new()
        .route("/", page.clone())
        .route("/index.html", page.clone());
    for area in SPA_AREAS {
        router = router
            .route(&format!("/{area}"), page.clone())
            .route(&format!("/{area}/{{*rest}}"), page.clone());
    }
    router.fallback_service(ServeDir::new(dist))
}

/// `index.html` with the request's tenant (set by `tenancy::resolve_host`)
/// written into its head.
async fn index_page(index: Arc<Path>, req: Request) -> Response {
    let Ok(html) = tokio::fs::read_to_string(&*index).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let html = match req.extensions().get::<Tenant>() {
        Some(tenant) => with_tenant(&html, &tenant.slug),
        None => html,
    };
    // The tenant differs per host, and a new build must reach users at once.
    ([(header::CACHE_CONTROL, "no-cache")], Html(html)).into_response()
}

/// Inserts the tenant `<meta>` before `</head>`. Slugs are `[a-z0-9-]`
/// (DB CHECK), so the value needs no escaping.
fn with_tenant(html: &str, slug: &str) -> String {
    let meta = format!(r#"<meta name="{TENANT_META}" content="{slug}" />"#);
    html.replacen("</head>", &format!("{meta}</head>"), 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_meta_goes_into_the_head() {
        assert_eq!(
            with_tenant(
                "<html><head><title>x</title></head><body></body></html>",
                "acme"
            ),
            r#"<html><head><title>x</title><meta name="oauth-tenant" content="acme" /></head><body></body></html>"#
        );
        // No head: unchanged (the SPA then falls back to the host name).
        assert_eq!(with_tenant("<p>SPA</p>", "acme"), "<p>SPA</p>");
    }
}
