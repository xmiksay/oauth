//! Prometheus metrics: a request counter/latency middleware for the app router
//! and a separate listener exposing `/metrics`, kept off the public port.

use std::time::{Duration, Instant};

use anyhow::Context;
use axum::{
    Router,
    extract::{MatchedPath, Request},
    http::Method,
    middleware::Next,
    response::Response,
    routing::get,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

pub const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
pub const HTTP_REQUEST_DURATION: &str = "http_request_duration_seconds";

/// Installs the global recorder. Call once per process; tests skip it, in which
/// case the `metrics` macros are no-ops.
pub fn install() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("installing Prometheus recorder")?;
    // Histograms and summaries are only drained on upkeep; without it their
    // buckets grow unbounded between scrapes.
    let upkeep = handle.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            upkeep.run_upkeep();
        }
    });
    Ok(handle)
}

pub fn router(handle: PrometheusHandle) -> Router {
    Router::new().route("/metrics", get(move || async move { handle.render() }))
}

pub async fn track(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = method_label(req.method());
    // Label by route template, not raw path, to keep label cardinality bounded.
    // Fallback (static files, 404s) has no template and collapses to one value.
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let response = next.run(req).await;
    let labels = [
        ("method", method.to_owned()),
        ("path", path),
        ("status", response.status().as_u16().to_string()),
    ];
    metrics::counter!(HTTP_REQUESTS_TOTAL, &labels).increment(1);
    metrics::histogram!(HTTP_REQUEST_DURATION, &labels).record(start.elapsed().as_secs_f64());
    response
}

/// Clients may send arbitrary extension methods; passing them through would
/// let anyone mint unbounded time series.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_labels_are_bounded() {
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::OPTIONS), "OPTIONS");
        assert_eq!(method_label(&Method::TRACE), "other");
        let custom = Method::from_bytes(b"XYZZY1").unwrap();
        assert_eq!(method_label(&custom), "other");
    }
}
