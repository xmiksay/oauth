//! Fake upstream OpenID provider: an in-process axum server (discovery,
//! JWKS, token endpoint) the server under test talks to over real HTTP,
//! plus the browser-facing authorize step done in-process. `Tweak`s make
//! it misbehave in one specific way.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

/// Work the fake runs (once) while answering the next token request — to
/// change things on our side mid-exchange.
pub type Hook = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
use entity::enums::SigningAlg;
use jsonwebtoken::{EncodingKey, Header};
use oauth_server::{keys, oidc::pkce};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::browser::query_of;

pub const CLIENT_ID: &str = "our-rp";
pub const CLIENT_SECRET: &str = "upstream-secret_0123";

/// One way to misbehave.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Tweak {
    #[default]
    None,
    Issuer(String),
    Audience(Value),
    Azp(String),
    Nonce(String),
    /// Seconds added to `exp` (negative = expired).
    ExpOffset(i64),
    /// `iat` this far in the future.
    IatOffset(i64),
    /// Signed by a key the JWKS doesn't publish, under the published kid.
    WrongKey,
    /// Signed by a key with a kid the JWKS doesn't list.
    UnknownKid,
    /// `alg: HS256`, keyed with the client secret.
    Hs256,
    /// `alg: none`, no signature.
    AlgNone,
    /// The token endpoint refuses.
    TokenError,
    /// The discovery document names another issuer.
    DiscoveryIssuer,
}

/// The upstream account the next sign-in is for.
#[derive(Clone, Debug)]
pub struct Account {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    /// `auth_time` as seconds relative to now; `None` = no claim.
    pub auth_time: Option<i64>,
}

impl Account {
    pub fn new(sub: &str, email: &str) -> Self {
        Self {
            sub: sub.into(),
            email: Some(email.into()),
            email_verified: true,
            name: Some("Upstream Person".into()),
            amr: vec!["pwd".into()],
            acr: None,
            auth_time: None,
        }
    }
}

struct Grant {
    challenge: String,
    redirect_uri: String,
    nonce: String,
    account: Account,
}

struct Key {
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
}

struct Inner {
    issuer: String,
    key: Key,
    stray: Key,
    account: Account,
    tweak: Tweak,
    codes: HashMap<String, Grant>,
    /// `(client_id, client_secret, via)` of each token request.
    token_auth: Vec<(String, Option<String>, &'static str)>,
    jwks_fetches: usize,
    /// Query of the last authorization request.
    last_authorize: HashMap<String, String>,
    on_token: Option<Hook>,
}

#[derive(Clone)]
pub struct FakeIdp {
    pub issuer: String,
    inner: Arc<Mutex<Inner>>,
}

async fn es256() -> Key {
    let generated = keys::generate(SigningAlg::Es256).await.unwrap();
    Key {
        kid: generated.kid.clone(),
        encoding: EncodingKey::from_ec_der(&generated.private_der),
        jwk: generated.public_jwk,
    }
}

async fn discovery(State(inner): State<Arc<Mutex<Inner>>>) -> Json<Value> {
    let inner = inner.lock().unwrap();
    let issuer = if inner.tweak == Tweak::DiscoveryIssuer {
        format!("{}/other", inner.issuer)
    } else {
        inner.issuer.clone()
    };
    let base = &inner.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
    }))
}

async fn jwks(State(inner): State<Arc<Mutex<Inner>>>) -> Json<Value> {
    let mut inner = inner.lock().unwrap();
    inner.jwks_fetches += 1;
    // An encryption key and junk ride along: they must be skipped.
    Json(json!({ "keys": [
        { "kty": "RSA", "use": "enc", "kid": "enc-1", "n": "AQAB", "e": "AQAB" },
        { "kty": "weird" },
        inner.key.jwk,
    ]}))
}

fn b64(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn id_token(inner: &Inner, grant: &Grant) -> String {
    let now = chrono::Utc::now().timestamp();
    let a = &grant.account;
    let mut claims = json!({
        "iss": inner.issuer, "aud": CLIENT_ID, "sub": a.sub, "nonce": grant.nonce,
        "iat": now, "exp": now + 300, "amr": a.amr,
    });
    if let Some(email) = &a.email {
        claims["email"] = json!(email);
        claims["email_verified"] = json!(a.email_verified);
    }
    if let Some(name) = &a.name {
        claims["name"] = json!(name);
    }
    if let Some(offset) = a.auth_time {
        claims["auth_time"] = json!(now + offset);
    }
    if let Some(acr) = &a.acr {
        claims["acr"] = json!(acr);
    }
    match &inner.tweak {
        Tweak::Issuer(iss) => claims["iss"] = json!(iss),
        Tweak::Audience(aud) => claims["aud"] = aud.clone(),
        Tweak::Azp(azp) => claims["azp"] = json!(azp),
        Tweak::Nonce(nonce) => claims["nonce"] = json!(nonce),
        Tweak::ExpOffset(secs) => claims["exp"] = json!(now + secs),
        Tweak::IatOffset(secs) => claims["iat"] = json!(now + secs),
        _ => {}
    }
    let sign = |key: &Key, kid: &str| {
        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(kid.to_owned());
        jsonwebtoken::encode(&header, &claims, &key.encoding).unwrap()
    };
    match inner.tweak {
        Tweak::WrongKey => sign(&inner.stray, &inner.key.kid),
        Tweak::UnknownKid => sign(&inner.stray, &inner.stray.kid),
        Tweak::Hs256 => {
            let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
            header.kid = Some(inner.key.kid.clone());
            let key = EncodingKey::from_secret(CLIENT_SECRET.as_bytes());
            jsonwebtoken::encode(&header, &claims, &key).unwrap()
        }
        Tweak::AlgNone => {
            let header = json!({ "alg": "none", "kid": inner.key.kid });
            format!("{}.{}.", b64(&header), b64(&claims))
        }
        _ => sign(&inner.key, &inner.key.kid),
    }
}

async fn token(
    State(inner): State<Arc<Mutex<Inner>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let hook = inner.lock().unwrap().on_token.take();
    if let Some(hook) = hook {
        hook().await;
    }
    answer(&inner, &headers, &form)
}

fn answer(
    inner: &Arc<Mutex<Inner>>,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let mut inner = inner.lock().unwrap();
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .map(|b| String::from_utf8(STANDARD.decode(b).unwrap()).unwrap());
    let (client, secret, via) = match basic {
        Some(pair) => {
            let (id, secret) = pair.split_once(':').unwrap();
            (id.to_owned(), Some(secret.to_owned()), "basic")
        }
        None => (
            form.get("client_id").cloned().unwrap_or_default(),
            form.get("client_secret").cloned(),
            "post",
        ),
    };
    inner.token_auth.push((client.clone(), secret.clone(), via));
    let refuse = |error: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
    if inner.tweak == Tweak::TokenError {
        return refuse("invalid_grant");
    }
    if client != CLIENT_ID || secret.as_deref() != Some(CLIENT_SECRET) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_client" })),
        );
    }
    let code = form.get("code").cloned().unwrap_or_default();
    let Some(grant) = inner.codes.remove(&code) else {
        return refuse("invalid_grant");
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if !pkce::verify_s256(&verifier, &grant.challenge)
        || form.get("redirect_uri") != Some(&grant.redirect_uri)
        || form.get("grant_type").map(String::as_str) != Some("authorization_code")
    {
        return refuse("invalid_grant");
    }
    let id_token = id_token(&inner, &grant);
    (
        StatusCode::OK,
        Json(
            json!({ "access_token": "upstream-at", "token_type": "Bearer", "id_token": id_token }),
        ),
    )
}

impl FakeIdp {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let inner = Arc::new(Mutex::new(Inner {
            issuer: issuer.clone(),
            key: es256().await,
            stray: es256().await,
            account: Account::new("upstream-sub-1", "pat@upstream.example"),
            tweak: Tweak::None,
            codes: HashMap::new(),
            token_auth: Vec::new(),
            jwks_fetches: 0,
            last_authorize: HashMap::new(),
            on_token: None,
        }));
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(inner.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { issuer, inner }
    }

    pub fn set_account(&self, account: Account) {
        self.inner.lock().unwrap().account = account;
    }

    pub fn tweak(&self, tweak: Tweak) {
        self.inner.lock().unwrap().tweak = tweak;
    }

    /// Publishes a fresh key and signs with it (a key rotation).
    pub async fn rotate(&self) {
        let key = es256().await;
        self.inner.lock().unwrap().key = key;
    }

    /// Runs `hook` during the next token request.
    pub fn on_token(&self, hook: Hook) {
        self.inner.lock().unwrap().on_token = Some(hook);
    }

    pub fn last_authorize(&self) -> HashMap<String, String> {
        self.inner.lock().unwrap().last_authorize.clone()
    }

    pub fn jwks_fetches(&self) -> usize {
        self.inner.lock().unwrap().jwks_fetches
    }

    pub fn token_auth(&self) -> Vec<(String, Option<String>, &'static str)> {
        self.inner.lock().unwrap().token_auth.clone()
    }

    /// The user approves at the provider: checks the authorization request
    /// `url` and returns the redirect back to us (`redirect_uri?code&state`).
    pub fn authorize(&self, url: &str) -> String {
        assert!(
            url.starts_with(&format!("{}/authorize?", self.issuer)),
            "{url}"
        );
        let q = query_of(url);
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["response_mode"], "query");
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(q["scope"].split(' ').any(|s| s == "openid"));
        let code = format!("code-{}", oauth_server::secret::random_token().unwrap());
        let mut inner = self.inner.lock().unwrap();
        let grant = Grant {
            challenge: q["code_challenge"].clone(),
            redirect_uri: q["redirect_uri"].clone(),
            nonce: q["nonce"].clone(),
            account: inner.account.clone(),
        };
        inner.codes.insert(code.clone(), grant);
        inner.last_authorize = q.clone();
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code)
            .append_pair("state", &q["state"])
            .finish();
        format!("{}?{query}", q["redirect_uri"])
    }
}
