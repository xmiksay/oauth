//! The authorization-code exchange at an upstream token endpoint (with
//! PKCE). Only the ID token is kept; upstream access / refresh tokens are
//! dropped with the response.

use base64::{Engine, engine::general_purpose::STANDARD};
use entity::enums::IdpClientAuth;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{Failure, MAX_RESPONSE_BYTES, Upstream, discovery::Metadata, urls};
use crate::http;

pub struct Exchange<'a> {
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub verifier: &'a str,
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub auth: IdpClientAuth,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// RFC 6749 §2.3.1: both halves are form-urlencoded before Basic encoding.
fn basic_credentials(client_id: &str, secret: &str) -> Zeroizing<String> {
    let enc = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let pair = Zeroizing::new(format!("{}:{}", enc(client_id), enc(secret)));
    Zeroizing::new(format!("Basic {}", STANDARD.encode(pair.as_bytes())))
}

impl Upstream {
    /// Redeems `ex.code`; returns the ID token.
    pub async fn exchange_code(
        &self,
        meta: &Metadata,
        ex: Exchange<'_>,
    ) -> Result<Zeroizing<String>, Failure> {
        let url = urls::checked(&meta.token_endpoint, self.allow_http_loopback)
            .ok_or(Failure("token_endpoint"))?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", ex.code),
            ("redirect_uri", ex.redirect_uri),
            ("code_verifier", ex.verifier),
        ];
        let mut request = self
            .http
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json");
        match (ex.auth, ex.client_secret) {
            (IdpClientAuth::Basic, Some(secret)) => {
                let value = basic_credentials(ex.client_id, secret);
                request = request.header(reqwest::header::AUTHORIZATION, value.as_str());
            }
            (_, secret) => {
                form.push(("client_id", ex.client_id));
                if let Some(secret) = secret {
                    form.push(("client_secret", secret));
                }
            }
        }
        let body = Zeroizing::new(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&form)
                .finish(),
        );
        let response = request
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body.as_bytes().to_vec())
            .send()
            .await
            .map_err(|err| {
                tracing::warn!(
                    timeout = err.is_timeout(),
                    "upstream token endpoint unreachable"
                );
                Failure("token_endpoint")
            })?;
        let status = response.status();
        if !status.is_success() {
            tracing::warn!(status = status.as_u16(), "upstream token endpoint refused");
            return Err(Failure("token_refused"));
        }
        let raw = Zeroizing::new(
            http::read_capped(response, MAX_RESPONSE_BYTES)
                .await
                .map_err(|_| Failure("token_response"))?,
        );
        let parsed: TokenResponse =
            serde_json::from_slice(&raw).map_err(|_| Failure("token_response"))?;
        parsed
            .id_token
            .map(Zeroizing::new)
            .ok_or(Failure("token_response_no_id_token"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_are_form_encoded_first() {
        let value = basic_credentials("a b", "p:w&");
        let decoded = STANDARD
            .decode(value.strip_prefix("Basic ").unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "a+b:p%3Aw%26");
    }
}
