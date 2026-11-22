//! The logout token (OIDC Back-Channel Logout 1.0 §2.4): a JWT with
//! `typ: logout+jwt`, the logout event, `sid` and `sub`, and never a
//! `nonce` (so it can't pass as an ID token).

use serde_json::{Map, Value, json};
use uuid::Uuid;

pub const TYP: &str = "logout+jwt";
pub const EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// Short: a logout token only has to survive the POST that carries it.
pub const TTL_SECS: i64 = 120;

pub struct Input<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub sid: Uuid,
    pub sub: Uuid,
    pub iat: i64,
    pub jti: Uuid,
}

pub fn claims(input: &Input<'_>) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("iss".into(), input.issuer.into());
    claims.insert("aud".into(), input.client_id.into());
    claims.insert("iat".into(), input.iat.into());
    claims.insert("exp".into(), (input.iat + TTL_SECS).into());
    claims.insert("jti".into(), input.jti.to_string().into());
    claims.insert("sub".into(), input.sub.to_string().into());
    claims.insert("sid".into(), input.sid.to_string().into());
    claims.insert("events".into(), json!({ EVENT: {} }));
    claims
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_follow_the_spec() {
        let (sid, sub, jti) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let c = claims(&Input {
            issuer: "https://t.example",
            client_id: "web-app",
            sid,
            sub,
            iat: 1000,
            jti,
        });
        assert_eq!(c["iss"], "https://t.example");
        assert_eq!(c["aud"], "web-app");
        assert_eq!(c["iat"], 1000);
        assert_eq!(c["exp"], 1000 + TTL_SECS);
        assert_eq!(c["jti"], jti.to_string());
        assert_eq!(c["sid"], sid.to_string());
        assert_eq!(c["sub"], sub.to_string());
        assert_eq!(c["events"], json!({ EVENT: {} }));
        assert!(c.get("nonce").is_none());
    }
}
