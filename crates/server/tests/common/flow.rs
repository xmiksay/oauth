//! OIDC test harness: a fixture tenant with apps and a user (the browser
//! side lives in `browser.rs`).

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use entity::{
    applications,
    enums::{AccessTokenFormat, ClientType, SigningAlg},
    group_members, groups, tenants, users,
};
use jsonwebtoken::{DecodingKey, Validation, jwk::JwkSet};
use oauth_server::{
    app::{self, AppState},
    authn::totp,
    config::Config,
    directory::{self, NewTenant},
};
use sea_orm::{ActiveValue::Set, DatabaseConnection};
use serde_json::Value;
use uuid::Uuid;

use super::browser::{Browser, send};
use super::seed::{add_app, add_role, add_scope, add_secret, add_user, assign_role, insert};
use super::{ORIGIN, TestDb};

pub const T: &str = "contoso";
pub const PASSWORD: &str = "correct horse battery";
pub const VERIFIER: &str = "test-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
pub const WEB_CB: &str = "https://web.example/cb";
pub const WEB_BYE: &str = "https://web.example/bye";
pub const SPA_CB: &str = "http://127.0.0.1/cb";
pub const TOTP_SECRET: &[u8] = b"12345678901234567890";

pub struct Fixture {
    pub _pg: TestDb,
    pub db: DatabaseConnection,
    pub config: Config,
    pub app: Router,
    pub tenant: tenants::Model,
    pub user: users::Model,
    pub group: Uuid,
    /// Resource `api://orders` (JWT, ES256): scopes `Orders.Read` (user) and
    /// `Orders.Manage` (admin consent); roles `Orders.Approver` (user, given
    /// to the user's group) and `Orders.Sync` (application).
    pub orders: applications::Model,
    /// Resource `api://ledger` (opaque tokens): scope `Ledger.Read`.
    pub ledger: applications::Model,
    pub ledger_secret: String,
    /// Confidential client (RS256 ID tokens).
    pub web: applications::Model,
    pub web_secret: String,
    /// Public client with a loopback redirect.
    pub spa: applications::Model,
}

impl Fixture {
    pub async fn new() -> Self {
        let (pg, db, config) = super::migrated_db().await;
        let tenant = directory::create_tenant(
            &db,
            &config,
            NewTenant {
                slug: T,
                display_name: "Contoso",
            },
        )
        .await
        .unwrap();
        let user = add_user(&db, tenant.id, "ann@example.com", false).await;
        let tid = tenant.id;
        use AccessTokenFormat::{Jwt, Opaque};
        use ClientType::{Confidential, Public};
        let orders = add_app(
            &db,
            tid,
            "orders",
            Confidential,
            Some("api://orders"),
            Jwt,
            SigningAlg::Es256,
        )
        .await;
        add_scope(&db, &orders, "Orders.Read", false).await;
        add_scope(&db, &orders, "Orders.Write", false).await;
        add_scope(&db, &orders, "Orders.Manage", true).await;
        let approver = add_role(&db, &orders, "Orders.Approver", "user").await;
        let ledger = add_app(
            &db,
            tid,
            "ledger",
            Confidential,
            Some("api://ledger"),
            Opaque,
            SigningAlg::Rs256,
        )
        .await;
        add_scope(&db, &ledger, "Ledger.Read", false).await;
        let web = add_app(
            &db,
            tid,
            "web-app",
            Confidential,
            None,
            Jwt,
            SigningAlg::Rs256,
        )
        .await;
        let spa = add_app(&db, tid, "spa-app", Public, None, Jwt, SigningAlg::Rs256).await;
        let web_secret = add_secret(&db, &web).await;
        let ledger_secret = add_secret(&db, &ledger).await;

        let group = insert(
            &db,
            groups::ActiveModel {
                id: Set(Uuid::now_v7()),
                tenant_id: Set(tid),
                display_name: Set("Approvers".into()),
                description: Set(None),
                ..Default::default()
            },
        )
        .await
        .id;
        insert(
            &db,
            group_members::ActiveModel {
                tenant_id: Set(tid),
                group_id: Set(group),
                user_id: Set(user.id),
                ..Default::default()
            },
        )
        .await;
        assign_role(&db, &orders, approver, Some(group), None).await;

        let app = app::router(
            AppState::new(db.clone(), config.clone(), true),
            super::no_web_dist(),
        );
        Self {
            _pg: pg,
            db,
            config,
            app,
            tenant,
            user,
            group,
            orders,
            ledger,
            ledger_secret,
            web,
            web_secret,
            spa,
        }
    }

    pub fn browser(&self) -> Browser {
        Browser::new(self.app.clone())
    }

    pub async fn enroll_totp(&self, user: &users::Model) {
        let sealed = totp::seal_secret(
            &self.config.master_key,
            user.tenant_id,
            user.id,
            TOTP_SECRET,
        )
        .unwrap();
        assert!(
            totp::store(&self.db, user.tenant_id, user.id, sealed, true)
                .await
                .unwrap()
        );
    }

    /// POSTs a form to a back-channel endpoint, optionally with Basic auth.
    pub async fn post_form(
        &self,
        path: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> (StatusCode, HeaderMap, Value) {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut req =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some((id, secret)) = basic {
            req = req.header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            );
        }
        let (status, headers, text) = send(&self.app, req.body(Body::from(body)).unwrap()).await;
        (
            status,
            headers,
            serde_json::from_str(&text).unwrap_or(Value::Null),
        )
    }

    /// Exchanges a code at the token endpoint.
    /// Interactive login for `web-app` in a fresh browser, then the token
    /// response. Returns the browser too (it holds the session).
    pub async fn web_tokens(&self, scope: &str, email: &str) -> (Browser, Value) {
        let mut browser = self.browser();
        let url = super::browser::authorize_url("web-app", WEB_CB, scope, &[]);
        let code = browser.login_for_code(&url, email).await;
        let (status, tokens) = self
            .redeem(&self.web, Some(&self.web_secret), &code, WEB_CB)
            .await;
        assert_eq!(status, StatusCode::OK, "{tokens}");
        (browser, tokens)
    }

    /// Refresh grant as `web-app`.
    pub async fn refresh(&self, token: &str, scope: Option<&str>) -> (StatusCode, Value) {
        let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", token)];
        if let Some(scope) = scope {
            form.push(("scope", scope));
        }
        let basic = Some(("web-app", self.web_secret.as_str()));
        let (status, _, body) = self.post_form("/oauth2/token", &form, basic).await;
        (status, body)
    }

    pub async fn redeem(
        &self,
        client: &applications::Model,
        secret: Option<&str>,
        code: &str,
        redirect_uri: &str,
    ) -> (StatusCode, Value) {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", VERIFIER),
        ];
        let basic = secret.map(|s| (client.client_id.as_str(), s));
        if basic.is_none() {
            form.push(("client_id", &client.client_id));
        }
        let (status, _, body) = self.post_form("/oauth2/token", &form, basic).await;
        (status, body)
    }

    /// Decodes a JWT after verifying it against the tenant's JWKS.
    pub async fn verify_jwt(&self, token: &str, audience: &str) -> serde_json::Map<String, Value> {
        let (status, _, body) = send(
            &self.app,
            Request::get("/discovery/keys").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let jwks: JwkSet = serde_json::from_str(&body).unwrap();
        let header = jsonwebtoken::decode_header(token).unwrap();
        let jwk = jwks
            .find(header.kid.as_deref().unwrap())
            .expect("kid in JWKS");
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[ORIGIN]);
        jsonwebtoken::decode(token, &DecodingKey::from_jwk(jwk).unwrap(), &validation)
            .unwrap()
            .claims
    }
}
