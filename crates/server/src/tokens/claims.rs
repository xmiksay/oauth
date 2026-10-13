//! Claim sets (pure): RFC 9068 access tokens, OIDC ID tokens and userinfo.

use aws_lc_rs::digest::{SHA256, digest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use entity::users;
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// Entra's limit: above it the `groups` claim is replaced by an overage flag
/// and the resource must look memberships up itself.
pub const MAX_GROUPS: usize = 200;
pub const TOKEN_VERSION: &str = "2.0";

/// The signed-in user behind a delegated token.
pub struct UserContext<'a> {
    pub user: &'a users::Model,
    pub session_id: Uuid,
    pub amr: &'a [String],
    /// Unix seconds.
    pub auth_time: i64,
}

pub struct AccessInput<'a> {
    pub issuer: &'a str,
    pub tenant_id: Uuid,
    pub audience: &'a str,
    pub client_id: &'a str,
    /// `None` = app-only token (client credentials).
    pub user: Option<UserContext<'a>>,
    /// Object id of the client app (subject of app-only tokens).
    pub client_object_id: Uuid,
    pub scopes: &'a [String],
    pub roles: &'a [String],
    pub groups: &'a [Uuid],
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
}

pub fn access_token(input: &AccessInput<'_>) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("iss".into(), input.issuer.into());
    claims.insert("aud".into(), input.audience.into());
    claims.insert("iat".into(), input.iat.into());
    claims.insert("nbf".into(), input.iat.into());
    claims.insert("exp".into(), input.exp.into());
    claims.insert("jti".into(), input.jti.to_string().into());
    claims.insert("client_id".into(), input.client_id.into());
    claims.insert("azp".into(), input.client_id.into());
    claims.insert("tid".into(), input.tenant_id.to_string().into());
    claims.insert("ver".into(), TOKEN_VERSION.into());
    match &input.user {
        Some(user) => {
            let oid = user.user.id.to_string();
            claims.insert("sub".into(), oid.clone().into());
            claims.insert("oid".into(), oid.into());
            claims.insert("sid".into(), user.session_id.to_string().into());
            claims.insert("amr".into(), json!(user.amr));
            claims.insert("auth_time".into(), user.auth_time.into());
            claims.insert("idtyp".into(), "user".into());
            // Delegated tokens carry `scp` even when empty-handed resources
            // only grant roles; app-only tokens never do.
            claims.insert("scp".into(), input.scopes.join(" ").into());
            insert_groups(&mut claims, input.groups);
        }
        None => {
            let oid = input.client_object_id.to_string();
            claims.insert("sub".into(), oid.clone().into());
            claims.insert("oid".into(), oid.into());
            claims.insert("idtyp".into(), "app".into());
        }
    }
    if !input.roles.is_empty() {
        claims.insert("roles".into(), json!(input.roles));
    }
    claims
}

fn insert_groups(claims: &mut Map<String, Value>, groups: &[Uuid]) {
    if groups.len() > MAX_GROUPS {
        claims.insert("hasgroups".into(), true.into());
    } else if !groups.is_empty() {
        let ids: Vec<String> = groups.iter().map(Uuid::to_string).collect();
        claims.insert("groups".into(), json!(ids));
    }
}

pub struct IdTokenInput<'a> {
    pub issuer: &'a str,
    pub tenant_id: Uuid,
    pub client_id: &'a str,
    pub user: UserContext<'a>,
    pub nonce: Option<&'a str>,
    pub oidc_scopes: &'a [String],
    pub access_token: &'a str,
    pub iat: i64,
    pub exp: i64,
}

pub fn id_token(input: &IdTokenInput<'_>) -> Map<String, Value> {
    let mut claims = profile_claims(input.user.user, input.oidc_scopes);
    let oid = input.user.user.id.to_string();
    claims.insert("iss".into(), input.issuer.into());
    claims.insert("aud".into(), input.client_id.into());
    claims.insert("azp".into(), input.client_id.into());
    claims.insert("iat".into(), input.iat.into());
    claims.insert("exp".into(), input.exp.into());
    claims.insert("oid".into(), oid.into());
    claims.insert("tid".into(), input.tenant_id.to_string().into());
    claims.insert("sid".into(), input.user.session_id.to_string().into());
    claims.insert("amr".into(), json!(input.user.amr));
    claims.insert("auth_time".into(), input.user.auth_time.into());
    claims.insert("ver".into(), TOKEN_VERSION.into());
    claims.insert("at_hash".into(), at_hash(input.access_token).into());
    if let Some(nonce) = input.nonce {
        claims.insert("nonce".into(), nonce.into());
    }
    claims
}

/// OIDC Core §3.1.3.6 for SHA-256 based algs (RS256 and ES256 alike).
pub fn at_hash(access_token: &str) -> String {
    let hash = digest(&SHA256, access_token.as_bytes());
    let left = hash.as_ref().get(..16).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(left)
}

/// `sub` plus the claims the `profile` / `email` scopes release (userinfo
/// and ID token share this).
pub fn profile_claims(user: &users::Model, oidc_scopes: &[String]) -> Map<String, Value> {
    let has = |s: &str| oidc_scopes.iter().any(|x| x == s);
    let mut claims = Map::new();
    claims.insert("sub".into(), user.id.to_string().into());
    if has("profile") {
        claims.insert("name".into(), user.display_name.clone().into());
        claims.insert("preferred_username".into(), user.email.clone().into());
    }
    if has("email") {
        claims.insert("email".into(), user.email.clone().into());
        claims.insert("email_verified".into(), user.email_verified.into());
    }
    claims
}

#[cfg(test)]
mod tests {
    use entity::enums::UserType;

    use super::*;

    fn user() -> users::Model {
        let now = chrono::Utc::now().fixed_offset();
        users::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            user_type: UserType::Member,
            email: "ann@example.com".into(),
            email_verified: true,
            display_name: "Ann".into(),
            password_hash: None,
            must_change_password: false,
            disabled: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn input<'a>(
        user: Option<UserContext<'a>>,
        groups: &'a [Uuid],
        scopes: &'a [String],
        roles: &'a [String],
    ) -> AccessInput<'a> {
        AccessInput {
            issuer: "https://id/t",
            tenant_id: Uuid::nil(),
            audience: "api://orders",
            client_id: "web",
            user,
            client_object_id: Uuid::max(),
            scopes,
            roles,
            groups,
            iat: 100,
            exp: 200,
            jti: Uuid::nil(),
        }
    }

    #[test]
    fn delegated_access_token() {
        let u = user();
        let amr = vec!["pwd".to_owned()];
        let ctx = UserContext {
            user: &u,
            session_id: Uuid::nil(),
            amr: &amr,
            auth_time: 90,
        };
        let scopes = vec!["read".to_owned(), "write".to_owned()];
        let roles = vec!["Admin".to_owned()];
        let groups = [Uuid::nil()];
        let c = access_token(&input(Some(ctx), &groups, &scopes, &roles));
        assert_eq!(c["sub"], u.id.to_string());
        assert_eq!(c["oid"], c["sub"]);
        assert_eq!(c["scp"], "read write");
        assert_eq!(c["roles"], json!(["Admin"]));
        assert_eq!(c["groups"], json!([Uuid::nil().to_string()]));
        assert_eq!(c["aud"], "api://orders");
        assert_eq!(c["azp"], "web");
        assert_eq!(c["client_id"], "web");
        assert_eq!(c["auth_time"], 90);
        assert_eq!(c["ver"], "2.0");
        assert!(c.get("hasgroups").is_none());
    }

    #[test]
    fn app_only_token_has_no_scp_and_idtyp_app() {
        let roles = vec!["Directory.Read.All".to_owned()];
        let c = access_token(&input(None, &[], &[], &roles));
        assert_eq!(c["idtyp"], "app");
        assert_eq!(c["sub"], Uuid::max().to_string());
        assert!(c.get("scp").is_none());
        assert!(c.get("sid").is_none());
        assert_eq!(c["roles"], json!(["Directory.Read.All"]));
        let c = access_token(&input(None, &[], &[], &[]));
        assert!(c.get("roles").is_none());
    }

    #[test]
    fn group_overage_becomes_a_flag() {
        let u = user();
        let ctx = |u| UserContext {
            user: u,
            session_id: Uuid::nil(),
            amr: &[],
            auth_time: 0,
        };
        let at_cap: Vec<Uuid> = (0..MAX_GROUPS).map(|_| Uuid::now_v7()).collect();
        let c = access_token(&input(Some(ctx(&u)), &at_cap, &[], &[]));
        assert_eq!(c["groups"].as_array().unwrap().len(), MAX_GROUPS);
        let over: Vec<Uuid> = (0..=MAX_GROUPS).map(|_| Uuid::now_v7()).collect();
        let c = access_token(&input(Some(ctx(&u)), &over, &[], &[]));
        assert!(c.get("groups").is_none());
        assert_eq!(c["hasgroups"], true);
        let c = access_token(&input(Some(ctx(&u)), &[], &[], &[]));
        assert!(c.get("groups").is_none() && c.get("hasgroups").is_none());
    }

    #[test]
    fn id_token_and_profile_claims() {
        let u = user();
        let amr = vec!["pwd".to_owned(), "mfa".to_owned()];
        let scopes = vec!["openid".to_owned(), "email".to_owned()];
        let c = id_token(&IdTokenInput {
            issuer: "https://id/t",
            tenant_id: Uuid::nil(),
            client_id: "web",
            user: UserContext {
                user: &u,
                session_id: Uuid::nil(),
                amr: &amr,
                auth_time: 5,
            },
            nonce: Some("n-1"),
            oidc_scopes: &scopes,
            access_token: "token",
            iat: 10,
            exp: 20,
        });
        assert_eq!(c["aud"], "web");
        assert_eq!(c["nonce"], "n-1");
        assert_eq!(c["email"], "ann@example.com");
        assert_eq!(c["email_verified"], true);
        assert!(c.get("name").is_none(), "profile scope not granted");
        assert_eq!(c["amr"], json!(["pwd", "mfa"]));
        assert_eq!(c["at_hash"], at_hash("token"));
        let profile = profile_claims(&u, &["profile".to_owned()]);
        assert_eq!(profile["name"], "Ann");
        assert!(profile.get("email").is_none());
    }

    #[test]
    fn at_hash_is_left_half_of_sha256() {
        // base64url(left 128 bits of SHA-256("abc")).
        assert_eq!(at_hash("abc"), "ungWv48Bz-pBQUDeXa4iIw");
    }
}
