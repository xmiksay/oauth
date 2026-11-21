//! CORS test helpers: the fixture with one explicit origin, plain and
//! preflight requests, and the header assertions.

use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use entity::applications;
use sea_orm::{ActiveModelTrait, ActiveValue::Set};

use super::{browser::send, flow::Fixture};

/// `spa-app` (public) gets this from its `https://web.example/cb` redirect.
pub const SPA_ORIGIN: &str = "https://web.example";
/// Explicitly allowed on the confidential `web-app` only.
pub const WEB_ORIGIN: &str = "https://portal.example";
pub const FOREIGN: &str = "https://evil.example";
pub const ACAO: header::HeaderName = header::ACCESS_CONTROL_ALLOW_ORIGIN;

pub async fn request(
    f: &Fixture,
    method: Method,
    uri: &str,
    headers: &[(header::HeaderName, &str)],
    form: Option<&[(&str, &str)]>,
) -> (StatusCode, HeaderMap) {
    let mut req = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        req = req.header(name, *value);
    }
    let body = match form {
        Some(form) => {
            req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(form)
                    .finish(),
            )
        }
        None => Body::empty(),
    };
    let (status, headers, _) = send(&f.app, req.body(body).unwrap()).await;
    (status, headers)
}

pub fn acao(headers: &HeaderMap) -> Option<&str> {
    headers.get(ACAO).map(|v| v.to_str().unwrap())
}

pub fn assert_cors(headers: &HeaderMap, allowed: Option<&str>, what: &str) {
    assert_eq!(acao(headers), allowed, "{what}");
    let vary: Vec<_> = headers.get_all(header::VARY).iter().collect();
    assert!(vary.iter().any(|v| *v == "Origin"), "{what}: Vary {vary:?}");
    assert!(
        !headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        "{what}"
    );
}

pub async fn fixture() -> Fixture {
    let f = Fixture::new().await;
    let mut web: applications::ActiveModel = f.web.clone().into();
    web.web_origins = Set(vec![WEB_ORIGIN.into()]);
    web.update(&f.db).await.unwrap();
    f
}

pub async fn preflight(f: &Fixture, uri: &str, origin: &str, method: &str) -> HeaderMap {
    let headers = [
        (header::ORIGIN, origin),
        (header::ACCESS_CONTROL_REQUEST_METHOD, method),
        (header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization"),
    ];
    let (status, out) = request(f, Method::OPTIONS, uri, &headers, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{uri}");
    out
}
