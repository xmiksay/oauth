//! Fake GitHub (OAuth 2.0, no OpenID): the token endpoint and the REST API
//! (`/api/v3/user`, `/api/v3/user/emails`, GitHub Enterprise Server paths)
//! over real HTTP; the browser-facing authorize step is in-process.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use oauth_server::oidc::pkce;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::{
    browser::query_of,
    upstream::{CLIENT_ID, CLIENT_SECRET},
};

const TOKEN: &str = "gho_fake-access-token";

#[derive(Default)]
struct Inner {
    user: Value,
    emails: Value,
    /// `(challenge, redirect_uri)` by code.
    codes: HashMap<String, (String, String)>,
    /// Whether every API call carried a `User-Agent`.
    user_agent_seen: bool,
}

#[derive(Clone)]
pub struct FakeGithub {
    /// The web origin (the IdP's `issuer`).
    pub base: String,
    inner: Arc<Mutex<Inner>>,
}

type Shared = State<Arc<Mutex<Inner>>>;

async fn token(
    State(inner): Shared,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut inner = inner.lock().unwrap();
    // Like GitHub: a bad code is a 200 with an `error`.
    let refuse = |error: &str| (StatusCode::OK, Json(json!({ "error": error })));
    if form.get("client_id").map(String::as_str) != Some(CLIENT_ID)
        || form.get("client_secret").map(String::as_str) != Some(CLIENT_SECRET)
    {
        return refuse("incorrect_client_credentials");
    }
    let code = form.get("code").cloned().unwrap_or_default();
    let Some((challenge, redirect_uri)) = inner.codes.remove(&code) else {
        return refuse("bad_verification_code");
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if !pkce::verify_s256(&verifier, &challenge) || form.get("redirect_uri") != Some(&redirect_uri)
    {
        return refuse("bad_verification_code");
    }
    let body =
        json!({ "access_token": TOKEN, "token_type": "bearer", "scope": "read:user,user:email" });
    (StatusCode::OK, Json(body))
}

fn authorized(inner: &mut Inner, headers: &HeaderMap) -> bool {
    inner.user_agent_seen = headers.contains_key(header::USER_AGENT);
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"))
}

async fn user(State(inner): Shared, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let mut inner = inner.lock().unwrap();
    if !authorized(&mut inner, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    (StatusCode::OK, Json(inner.user.clone()))
}

async fn emails(State(inner): Shared, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let mut inner = inner.lock().unwrap();
    if !authorized(&mut inner, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    (StatusCode::OK, Json(inner.emails.clone()))
}

impl FakeGithub {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let inner = Arc::new(Mutex::new(Inner::default()));
        let app = Router::new()
            .route("/login/oauth/access_token", post(token))
            .route("/api/v3/user", get(user))
            .route("/api/v3/user/emails", get(emails))
            .with_state(inner.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let fake = Self { base, inner };
        fake.set_account(
            json!({ "id": 583231, "login": "octocat", "name": "The Octocat" }),
            json!([
                { "email": "octo@secondary.example", "primary": false, "verified": true },
                { "email": "octo@github.example", "primary": true, "verified": true },
            ]),
        );
        fake
    }

    pub fn set_account(&self, user: Value, emails: Value) {
        let mut inner = self.inner.lock().unwrap();
        inner.user = user;
        inner.emails = emails;
    }

    pub fn user_agent_seen(&self) -> bool {
        self.inner.lock().unwrap().user_agent_seen
    }

    /// The user approves: checks the authorization request `url`, returns
    /// the redirect back to us.
    pub fn authorize(&self, url: &str) -> String {
        assert!(
            url.starts_with(&format!("{}/login/oauth/authorize?", self.base)),
            "{url}"
        );
        let q = query_of(url);
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["scope"], "read:user user:email");
        assert_eq!(q["code_challenge_method"], "S256");
        let code = format!("gh-{}", oauth_server::secret::random_token().unwrap());
        self.inner.lock().unwrap().codes.insert(
            code.clone(),
            (q["code_challenge"].clone(), q["redirect_uri"].clone()),
        );
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code)
            .append_pair("state", &q["state"])
            .finish();
        format!("{}?{query}", q["redirect_uri"])
    }
}
