//! In-process "browser" with a cookie jar, plus URL helpers for driving
//! the authorization flow.

use std::collections::HashMap;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use oauth_server::{authn::totp, oidc::pkce};
use serde_json::Value;
use tower::ServiceExt;

use super::{
    PUBLIC_URL,
    flow::{PASSWORD, T, TOTP_SECRET, VERIFIER},
};

pub async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = app.clone().oneshot(req).await.expect("infallible router");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Builds an authorize URL (path + query) with PKCE S256 for [`VERIFIER`].
/// `extra` pairs override defaults of the same name (empty value = drop).
pub fn authorize_url(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    extra: &[(&str, &str)],
) -> String {
    let challenge = pkce::challenge_for(VERIFIER);
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", scope),
        ("state", "st-1"),
        ("nonce", "n-1"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    for (key, value) in extra {
        pairs.retain(|(k, _)| k != key);
        if !value.is_empty() {
            pairs.push((key, value));
        }
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    format!("/{T}/oauth2/authorize?{query}")
}

/// Query parameters of a URL.
pub fn query_of(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

pub fn current_totp() -> String {
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    format!("{:06}", totp::hotp(TOTP_SECRET, now / totp::STEP_SECS))
}

pub struct Browser {
    app: Router,
    pub cookies: HashMap<String, String>,
}

impl Browser {
    pub fn has_session(&self) -> bool {
        self.cookies.contains_key("__Host-oauth_sid_contoso")
    }

    pub fn new(app: Router) -> Self {
        Self {
            app,
            cookies: HashMap::new(),
        }
    }

    pub async fn request(&mut self, mut req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        if !self.cookies.is_empty() {
            let jar: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            req.headers_mut()
                .insert(header::COOKIE, jar.join("; ").parse().unwrap());
        }
        let (status, headers, body) = send(&self.app, req).await;
        for set in headers.get_all(header::SET_COOKIE) {
            let set = set.to_str().unwrap();
            let (pair, attrs) = set.split_once(';').unwrap_or((set, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.into(), value.into());
            }
        }
        (status, headers, body)
    }

    /// GET; returns the status and the `Location` (relative to PUBLIC_URL if
    /// it points at us).
    pub async fn get(&mut self, path: &str) -> (StatusCode, Option<String>, String) {
        let (status, headers, body) = self
            .request(Request::get(path).body(Body::empty()).unwrap())
            .await;
        let location = headers
            .get(header::LOCATION)
            .map(|l| l.to_str().unwrap().to_owned());
        (status, location, body)
    }

    pub async fn post_json(
        &mut self,
        path: &str,
        body: &Value,
        origin: &str,
    ) -> (StatusCode, HeaderMap, Value) {
        let req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, origin)
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, headers, text) = self.request(req).await;
        (
            status,
            headers,
            serde_json::from_str(&text).unwrap_or(Value::Null),
        )
    }

    /// Calls a login API step with the right Origin.
    pub async fn step(&mut self, tx: &str, step: &str, body: Value) -> (StatusCode, Value) {
        let (status, _, value) = self
            .post_json(&format!("/{T}/api/authn/tx/{tx}/{step}"), &body, PUBLIC_URL)
            .await;
        (status, value)
    }

    /// Starts an authorization request; returns the tx id if it went to the
    /// login page, or `Err(redirect)` if it went straight back to the client.
    pub async fn authorize(&mut self, url: &str) -> Result<String, String> {
        let (status, location, body) = self.get(url).await;
        assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
        let location = location.unwrap();
        let login = format!("{PUBLIC_URL}/{T}/login?tx=");
        match location.strip_prefix(&login) {
            Some(tx) => Ok(tx.to_owned()),
            None => Err(location),
        }
    }

    /// Answers every step (password, TOTP, consent approval) until the flow
    /// redirects back; returns that redirect URL.
    pub async fn complete_login(&mut self, tx: &str, email: &str) -> String {
        let (status, _, _) = self.get(&format!("/{T}/api/authn/tx/{tx}")).await;
        assert_eq!(status, StatusCode::OK);
        let (mut status, mut resp) = self
            .step(
                tx,
                "password",
                serde_json::json!({ "email": email, "password": PASSWORD }),
            )
            .await;
        loop {
            assert_eq!(status, StatusCode::OK, "{resp}");
            if let Some(url) = resp["redirect"].as_str() {
                return url.to_owned();
            }
            (status, resp) = match resp["step"].as_str().unwrap() {
                "mfa" => {
                    self.step(tx, "totp", serde_json::json!({ "code": current_totp() }))
                        .await
                }
                "consent" => {
                    let scopes: Vec<Value> = resp["consent"]["scopes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s["value"].clone())
                        .collect();
                    self.step(
                        tx,
                        "consent",
                        serde_json::json!({ "approve": true, "scopes": scopes }),
                    )
                    .await
                }
                other => panic!("unexpected step {other}: {resp}"),
            };
        }
    }

    /// Full interactive flow; returns the code from the final redirect.
    pub async fn login_for_code(&mut self, url: &str, email: &str) -> String {
        let redirect = match self.authorize(url).await {
            Ok(tx) => self.complete_login(&tx, email).await,
            Err(redirect) => redirect,
        };
        let q = query_of(&redirect);
        assert_eq!(
            q.get("state").map(String::as_str),
            Some("st-1"),
            "{redirect}"
        );
        q.get("code")
            .cloned()
            .unwrap_or_else(|| panic!("no code in {redirect}"))
    }
}
