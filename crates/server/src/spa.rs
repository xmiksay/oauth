//! Serves the built Vue SPA (`web/dist`). Client-side routes under
//! `/{tenant}/login|logout|myaccount|admin` fall back to `index.html`; anything else
//! is looked up as a static asset.

use std::path::Path;

use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

/// `logout` is the sign-out confirmation page (`oidc::logout`).
const SPA_AREAS: [&str; 4] = ["login", "logout", "myaccount", "admin"];

pub fn router<S: Clone + Send + Sync + 'static>(dist: &Path) -> Router<S> {
    let index = dist.join("index.html");
    if !index.is_file() {
        // Not fatal: the API stays usable without a frontend build (e.g. in
        // backend-only dev); SPA paths just answer 404.
        tracing::warn!(dir = %dist.display(), "SPA build not found; frontend routes will 404");
    }
    let mut router = Router::new();
    for area in SPA_AREAS {
        router = router
            .route_service(&format!("/{{tenant}}/{area}"), ServeFile::new(&index))
            .route_service(
                &format!("/{{tenant}}/{area}/{{*rest}}"),
                ServeFile::new(&index),
            );
    }
    router.fallback_service(ServeDir::new(dist))
}
