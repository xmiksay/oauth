//! The browser's `PublicKeyCredential.toJSON()` shapes (base64url
//! members) and the options we send for `navigator.credentials.*`.

use entity::{users, webauthn_credentials};
use serde::Deserialize;
use serde_json::{Value, json};

use super::challenge::TTL_SECS;
use crate::webauthn::{
    self, MAX_ATTESTATION_OBJECT, MAX_AUTHENTICATOR_DATA, MAX_CLIENT_DATA, MAX_CREDENTIAL_ID,
    MAX_SIGNATURE, MAX_USER_HANDLE, Rp, SUPPORTED_ALGS, WebauthnError, b64_decode, b64_encode,
    client_data::{self, ClientData},
};

/// Transport hints we keep (WebAuthn §5.8.4); anything else is dropped.
const TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponseJson {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option<String>,
}

/// An assertion (`navigator.credentials.get`). Unknown members (e.g.
/// `clientExtensionResults`) are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionJson {
    id: String,
    raw_id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    response: AssertionResponseJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponseJson {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
    #[serde(default)]
    transports: Vec<String>,
}

/// A new credential (`navigator.credentials.create`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationJson {
    id: String,
    raw_id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    response: RegistrationResponseJson,
}

pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub client_data: ClientData,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

pub struct Registration {
    pub client_data: ClientData,
    pub attestation_object: Vec<u8>,
    pub transports: Vec<String>,
}

fn credential_id(id: &str, raw_id: Option<&str>, kind: &str) -> Result<Vec<u8>, WebauthnError> {
    if kind != "public-key" || raw_id.is_some_and(|raw| raw != id) {
        return Err(WebauthnError::Malformed("credential"));
    }
    let bytes = b64_decode(id, MAX_CREDENTIAL_ID, "credential id")?;
    if bytes.is_empty() {
        return Err(WebauthnError::Malformed("credential id"));
    }
    Ok(bytes)
}

impl AssertionJson {
    pub fn decode(&self) -> Result<Assertion, WebauthnError> {
        let r = &self.response;
        let client_data_json = b64_decode(&r.client_data_json, MAX_CLIENT_DATA, "client data")?;
        Ok(Assertion {
            credential_id: credential_id(&self.id, self.raw_id.as_deref(), &self.kind)?,
            client_data: client_data::parse(&client_data_json)?,
            client_data_json,
            authenticator_data: b64_decode(
                &r.authenticator_data,
                MAX_AUTHENTICATOR_DATA,
                "authenticator data",
            )?,
            signature: b64_decode(&r.signature, MAX_SIGNATURE, "signature")?,
            user_handle: r
                .user_handle
                .as_deref()
                .filter(|h| !h.is_empty())
                .map(|h| b64_decode(h, MAX_USER_HANDLE, "user handle"))
                .transpose()?,
        })
    }
}

impl RegistrationJson {
    pub fn decode(&self) -> Result<Registration, WebauthnError> {
        credential_id(&self.id, self.raw_id.as_deref(), &self.kind)?;
        let r = &self.response;
        let client_data_json = b64_decode(&r.client_data_json, MAX_CLIENT_DATA, "client data")?;
        let mut transports: Vec<String> = Vec::new();
        for t in r.transports.iter().take(16) {
            if TRANSPORTS.contains(&t.as_str()) && !transports.contains(t) {
                transports.push(t.clone());
            }
        }
        Ok(Registration {
            client_data: client_data::parse(&client_data_json)?,
            attestation_object: b64_decode(
                &r.attestation_object,
                MAX_ATTESTATION_OBJECT,
                "attestation object",
            )?,
            transports,
        })
    }
}

fn descriptors(credentials: &[webauthn_credentials::Model]) -> Vec<Value> {
    credentials
        .iter()
        .map(|c| {
            json!({
                "type": "public-key",
                "id": b64_encode(&c.credential_id),
                "transports": c.transports,
            })
        })
        .collect()
}

/// `PublicKeyCredentialCreationOptionsJSON`: a discoverable credential
/// (`residentKey: required`, so it works without typing an email) with
/// user verification, no attestation.
pub fn creation_options(
    rp: &Rp,
    rp_name: &str,
    user: &users::Model,
    handle: &[u8],
    challenge: &str,
    existing: &[webauthn_credentials::Model],
) -> Value {
    let params: Vec<Value> = SUPPORTED_ALGS
        .iter()
        .map(|alg| json!({ "type": "public-key", "alg": alg }))
        .collect();
    json!({ "publicKey": {
        "challenge": challenge,
        "rp": { "id": rp.id, "name": rp_name },
        "user": {
            "id": b64_encode(handle),
            "name": user.email,
            "displayName": user.display_name,
        },
        "pubKeyCredParams": params,
        "timeout": TTL_SECS * 1000,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "required",
        },
        "excludeCredentials": descriptors(existing),
    }})
}

/// `PublicKeyCredentialRequestOptionsJSON`; `allow` empty = any
/// discoverable credential for this RP (and conditional mediation).
pub fn request_options(rp: &Rp, challenge: &str, allow: &[webauthn_credentials::Model]) -> Value {
    json!({ "publicKey": {
        "challenge": challenge,
        "rpId": rp.id,
        "timeout": TTL_SECS * 1000,
        "userVerification": "required",
        "allowCredentials": descriptors(allow),
    }})
}

/// A passkey as the management API shows it.
pub fn view(c: &webauthn_credentials::Model) -> Value {
    json!({
        "id": c.id,
        "name": c.name,
        "created_at": crate::api::ts(&c.created_at),
        "last_used_at": c.last_used_at.as_ref().map(crate::api::ts),
        "backup_eligible": c.backup_eligible,
        "backup_state": c.backup_state,
        "transports": c.transports,
        "aaguid": c.aaguid,
    })
}

pub fn rp(config: &crate::config::Config, slug: &str) -> Rp {
    webauthn::Rp {
        id: config.tenant_rp_id(slug),
        origin: config.tenant_origin(slug),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assertion(id: &str, raw: Option<&str>, kind: &str) -> AssertionJson {
        let cd = b64_encode(br#"{"type":"webauthn.get","challenge":"abc","origin":"o"}"#);
        serde_json::from_value(json!({
            "id": id, "rawId": raw, "type": kind,
            "response": { "clientDataJSON": cd, "authenticatorData": "AA", "signature": "AA",
                          "userHandle": null },
            "clientExtensionResults": {},
        }))
        .unwrap()
    }

    #[test]
    fn assertion_ids_must_agree() {
        let ok = assertion("AQI", Some("AQI"), "public-key")
            .decode()
            .unwrap();
        assert_eq!(ok.credential_id, vec![1, 2]);
        assert_eq!(ok.client_data.challenge, "abc");
        assert!(ok.user_handle.is_none());
        assert!(
            assertion("AQI", Some("AQM"), "public-key")
                .decode()
                .is_err()
        );
        assert!(assertion("AQI", None, "password").decode().is_err());
        assert!(assertion("", None, "public-key").decode().is_err());
    }

    #[test]
    fn transports_are_filtered() {
        let cd = b64_encode(br#"{"type":"webauthn.create","challenge":"abc","origin":"o"}"#);
        let reg: RegistrationJson = serde_json::from_value(json!({
            "id": "AQ", "type": "public-key",
            "response": { "clientDataJSON": cd, "attestationObject": "oA",
                          "transports": ["usb", "bogus", "usb", "internal"] },
        }))
        .unwrap();
        assert_eq!(reg.decode().unwrap().transports, vec!["usb", "internal"]);
    }
}
