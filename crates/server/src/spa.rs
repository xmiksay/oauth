//! Serves the built Vue SPA (`web/dist`) on tenant hosts (the host gate in
//! `app.rs` keeps it off the apex unless `APEX_TENANT` puts a tenant there).
//! `/` (the portal / dashboard) and client-side routes under
//! `/login|logout|device|myaccount|admin` fall back to `index.html` (as does
//! `/index.html` itself, so every HTML entry point carries the tenant and
//! build metas); anything else is looked up as a static asset.

use std::{path::Path, sync::Arc};

use axum::{
    Router,
    extract::Request,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use tower_http::services::ServeDir;

use crate::{build_info, tenancy::Tenant};

/// `logout` is the sign-out confirmation page (`oidc::logout`), `device` the
/// device-code verification page (`verification_uri`).
const SPA_AREAS: [&str; 5] = ["login", "logout", "device", "myaccount", "admin"];

/// Name of the `<meta>` carrying the tenant's slug. WHY: the SPA can't tell
/// the tenant from the host name alone — on the apex (`APEX_TENANT`) the
/// first label is not a slug.
pub const TENANT_META: &str = "oauth-tenant";

/// Name of the `<meta>` carrying `<version>+<commit>` of this binary. WHY
/// from the server rather than baked into the bundle: the SPA can then never
/// show another build than the one serving it.
pub const BUILD_META: &str = "oauth-build";

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

/// `index.html` with the build and the request's tenant (set by
/// `tenancy::resolve_host`) written into its head.
async fn index_page(index: Arc<Path>, req: Request) -> Response {
    let Ok(html) = tokio::fs::read_to_string(&*index).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let tenant = req.extensions().get::<Tenant>().map(|t| t.slug.as_str());
    let html = with_metas(&html, tenant);
    // The tenant differs per host, and a new build must reach users at once.
    ([(header::CACHE_CONTROL, "no-cache")], Html(html)).into_response()
}

/// Inserts the build and (if any) tenant `<meta>`s before `</head>`.
fn with_metas(html: &str, tenant: Option<&str>) -> String {
    let build = format!("{}+{}", build_info::VERSION, build_info::COMMIT);
    let mut metas = meta(BUILD_META, &build);
    if let Some(slug) = tenant {
        metas.push_str(&meta(TENANT_META, slug));
    }
    html.replacen("</head>", &format!("{metas}</head>"), 1)
}

/// Values are escaped although slugs are `[a-z0-9-]` (DB CHECK) and the
/// build is semver + hex: a later source must not be able to break out of
/// the attribute.
fn meta(name: &str, content: &str) -> String {
    format!(
        r#"<meta name="{}" content="{}" />"#,
        escape_attr(name),
        escape_attr(content)
    )
}

fn escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "<html><head><title>x</title></head><body></body></html>";

    fn build_meta() -> String {
        format!(
            r#"<meta name="oauth-build" content="{}+{}" />"#,
            build_info::VERSION,
            build_info::COMMIT
        )
    }

    #[test]
    fn build_and_tenant_metas_go_into_the_head() {
        assert_eq!(
            with_metas(PAGE, Some("acme")),
            format!(
                r#"<html><head><title>x</title>{}<meta name="oauth-tenant" content="acme" /></head><body></body></html>"#,
                build_meta()
            )
        );
        // No head: unchanged (the SPA then falls back to the host name).
        assert_eq!(with_metas("<p>SPA</p>", Some("acme")), "<p>SPA</p>");
    }

    #[test]
    fn without_a_tenant_only_the_build_meta_is_written() {
        assert_eq!(
            with_metas(PAGE, None),
            format!(
                "<html><head><title>x</title>{}</head><body></body></html>",
                build_meta()
            )
        );
    }

    #[test]
    fn meta_values_are_escaped() {
        assert_eq!(
            meta("n", r#"a"><script>&'"#),
            r#"<meta name="n" content="a&quot;&gt;&lt;script&gt;&amp;&#39;" />"#
        );
    }
}
