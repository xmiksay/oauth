//! Federation test harness: the fixture tenant plus a fake upstream
//! provider configured through the management API, and helpers that drive
//! a browser through the upstream round trip.

use axum::http::{Method, StatusCode};
use entity::enums::DirectoryRole;
use serde_json::{Value, json};

use super::{
    ORIGIN,
    browser::{Browser, authorize_url, query_of},
    flow::{Fixture, WEB_CB},
    mgmt::{call, mint_user_token, user_with_roles},
    upstream::{CLIENT_ID, CLIENT_SECRET, FakeIdp},
};

pub const IDPS: &str = "/api/v1/identity-providers";

pub struct Fed {
    pub f: Fixture,
    pub up: FakeIdp,
    /// A GlobalAdmin's management token.
    pub admin: String,
}

impl Fed {
    pub async fn new() -> Self {
        Self::with(Fixture::new().await).await
    }

    pub async fn with(f: Fixture) -> Self {
        let up = FakeIdp::start().await;
        let ga = user_with_roles(
            &f.db,
            f.tenant.id,
            "ga@example.com",
            &[DirectoryRole::GlobalAdmin],
        )
        .await;
        let admin = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
        Self { f, up, admin }
    }

    /// The default IdP body (policy `jit`), with `extra` fields merged in.
    pub fn body(&self, extra: Value) -> Value {
        let mut body = json!({
            "name": "Upstream",
            "issuer": self.up.issuer,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "policy": "jit",
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        body
    }

    pub async fn api(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(&self.f.app, method, path, Some(&self.admin), body.as_ref()).await
    }

    /// Creates an IdP; returns its id.
    pub async fn idp(&self, extra: Value) -> String {
        let (status, body) = self.api(Method::POST, IDPS, Some(self.body(extra))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().to_owned()
    }

    pub async fn patch_idp(&self, id: &str, body: Value) -> Value {
        let (status, out) = self
            .api(Method::PATCH, &format!("{IDPS}/{id}"), Some(body))
            .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        out
    }

    /// A new login transaction (web-app, `openid profile email`).
    pub async fn authorize(&self, browser: &mut Browser, extra: &[(&str, &str)]) -> String {
        let url = authorize_url("web-app", WEB_CB, "openid profile email", extra);
        browser.authorize(&url).await.expect("login page")
    }

    /// `POST …/federation/{idp}` → the upstream authorization URL.
    pub async fn begin(&self, browser: &mut Browser, tx: &str, idp: &str) -> String {
        let (status, body) = browser
            .step(tx, &format!("federation/{idp}"), json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["redirect"].as_str().unwrap().to_owned()
    }

    /// The provider approves and the browser follows the callback;
    /// returns where the callback sent it.
    pub async fn come_back(&self, browser: &mut Browser, upstream_url: &str) -> String {
        let callback = self.up.authorize(upstream_url);
        follow(browser, &callback).await
    }

    /// A whole federated sign-in in a new transaction: `(tx, location)`.
    pub async fn sign_in(&self, browser: &mut Browser, idp: &str) -> (String, String) {
        let tx = self.authorize(browser, &[]).await;
        let url = self.begin(browser, &tx, idp).await;
        let location = self.come_back(browser, &url).await;
        (tx, location)
    }

    /// Redeems the code of a client redirect; returns the ID token's `amr`.
    pub async fn amr(&self, location: &str) -> Vec<String> {
        let code = code_of(location);
        let (status, tokens) = self
            .f
            .redeem(&self.f.web, Some(&self.f.web_secret), &code, WEB_CB)
            .await;
        assert_eq!(status, StatusCode::OK, "{tokens}");
        let claims = self
            .f
            .verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
            .await;
        serde_json::from_value(claims["amr"].clone()).unwrap()
    }
}

/// GETs a callback URL; returns the `Location` (always a redirect).
pub async fn follow(browser: &mut Browser, url: &str) -> String {
    let (status, location, body) = browser.get(url).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    location.unwrap()
}

/// The `code` of a redirect to the client.
pub fn code_of(location: &str) -> String {
    assert!(location.starts_with(WEB_CB), "{location}");
    query_of(location)["code"].clone()
}

/// `error` of a `/login?…` redirect (`None` = no error).
pub fn login_error(location: &str) -> Option<String> {
    assert!(
        location.starts_with(&format!("{ORIGIN}/login?")),
        "{location}"
    );
    query_of(location).get("error").cloned()
}

/// The login page of `tx` without an error.
pub fn is_login_page(location: &str, tx: &str) -> bool {
    location == format!("{ORIGIN}/login?tx={tx}")
}
