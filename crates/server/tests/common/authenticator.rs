//! A software WebAuthn authenticator (AWS-LC keys: P-256, Ed25519, RSA)
//! producing real attestation objects, client data and assertion
//! signatures, with knobs to produce every kind of bad response.

use aws_lc_rs::{
    digest::{SHA256, digest},
    rand::{SystemRandom, fill},
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value as Cbor;
use serde_json::{Value, json};

pub const UP: u8 = 0x01;
pub const UV: u8 = 0x04;
pub const BE: u8 = 0x08;
pub const BS: u8 = 0x10;
pub const AT: u8 = 0x40;

#[derive(Clone, Copy, Debug)]
pub enum Alg {
    Es256,
    EdDsa,
    Rs256,
}

enum Key {
    Es(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

/// Per-response deviations from a well-behaved authenticator / browser.
#[derive(Default, Clone)]
pub struct Tweak {
    pub origin: Option<String>,
    pub rp_id: Option<String>,
    /// Replaces the computed flags byte.
    pub flags: Option<u8>,
    pub client_type: Option<&'static str>,
    pub cross_origin: bool,
    /// Reports this counter instead of the next one.
    pub sign_count: Option<u32>,
    pub corrupt_signature: bool,
    /// Answers this challenge instead of the one in the options.
    pub challenge: Option<String>,
    /// Sends this COSE key instead of the real one.
    pub cose_key: Option<Vec<u8>>,
    /// `Some(None)`: no user handle; `Some(Some(h))`: this one.
    pub user_handle: Option<Option<Vec<u8>>>,
}

pub struct Authenticator {
    key: Key,
    alg: Alg,
    pub credential_id: Vec<u8>,
    /// Counter of the last signature; `None` = never counts (synced passkeys).
    pub counter: Option<u32>,
    pub user_handle: Option<Vec<u8>>,
    pub rp_id: String,
    pub origin: String,
    pub backup_eligible: bool,
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

fn cbor(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).unwrap();
    out
}

fn int(i: i64) -> Cbor {
    Cbor::Integer(i.into())
}

/// A COSE map from integer keys.
pub fn cose_map(entries: Vec<(i64, Cbor)>) -> Vec<u8> {
    cbor(&Cbor::Map(
        entries.into_iter().map(|(k, v)| (int(k), v)).collect(),
    ))
}

impl Authenticator {
    /// A counting, device-bound authenticator for tenant `slug`'s host.
    pub fn new(alg: Alg, slug: &str) -> Self {
        let key = match alg {
            Alg::Es256 => Key::Es(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap()),
            Alg::EdDsa => Key::Ed(Ed25519KeyPair::generate().unwrap()),
            Alg::Rs256 => Key::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).unwrap()),
        };
        let mut credential_id = vec![0u8; 16];
        fill(&mut credential_id).unwrap();
        Self {
            key,
            alg,
            credential_id,
            counter: Some(0),
            user_handle: None,
            rp_id: format!("{slug}.id.example.test"),
            origin: format!("https://{slug}.id.example.test"),
            backup_eligible: false,
        }
    }

    /// A synced passkey: backup-eligible and backed up, never counting.
    pub fn synced(alg: Alg, slug: &str) -> Self {
        Self {
            counter: None,
            backup_eligible: true,
            ..Self::new(alg, slug)
        }
    }

    pub fn cose_key(&self) -> Vec<u8> {
        match &self.key {
            Key::Es(pair) => {
                let point = pair.public_key().as_ref();
                cose_map(vec![
                    (1, int(2)),
                    (3, int(-7)),
                    (-1, int(1)),
                    (-2, Cbor::Bytes(point[1..33].to_vec())),
                    (-3, Cbor::Bytes(point[33..].to_vec())),
                ])
            }
            Key::Ed(pair) => cose_map(vec![
                (1, int(1)),
                (3, int(-8)),
                (-1, int(6)),
                (-2, Cbor::Bytes(pair.public_key().as_ref().to_vec())),
            ]),
            Key::Rsa(pair) => {
                let public = pair.public_key();
                cose_map(vec![
                    (1, int(3)),
                    (3, int(-257)),
                    (
                        -1,
                        Cbor::Bytes(public.modulus().big_endian_without_leading_zero().to_vec()),
                    ),
                    (
                        -2,
                        Cbor::Bytes(public.exponent().big_endian_without_leading_zero().to_vec()),
                    ),
                ])
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Es(pair) => pair
                .sign(&SystemRandom::new(), message)
                .unwrap()
                .as_ref()
                .to_vec(),
            Key::Ed(pair) => pair.sign(message).as_ref().to_vec(),
            Key::Rsa(pair) => {
                let mut sig = vec![0; pair.public_modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), message, &mut sig)
                    .unwrap();
                sig
            }
        }
    }

    pub fn alg(&self) -> Alg {
        self.alg
    }

    fn client_data(&self, kind: &str, options: &Value, tweak: &Tweak) -> Vec<u8> {
        let challenge = tweak.challenge.clone().unwrap_or_else(|| {
            options["publicKey"]["challenge"]
                .as_str()
                .unwrap()
                .to_owned()
        });
        json!({
            "type": tweak.client_type.unwrap_or(kind),
            "challenge": challenge,
            "origin": tweak.origin.clone().unwrap_or_else(|| self.origin.clone()),
            "crossOrigin": tweak.cross_origin,
        })
        .to_string()
        .into_bytes()
    }

    fn flags(&self, base: u8, tweak: &Tweak) -> u8 {
        let backup = if self.backup_eligible { BE | BS } else { 0 };
        tweak.flags.unwrap_or(base | backup)
    }

    fn auth_data_head(&self, flags: u8, count: u32, tweak: &Tweak) -> Vec<u8> {
        let rp_id = tweak.rp_id.clone().unwrap_or_else(|| self.rp_id.clone());
        let mut out = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
        out.push(flags);
        out.extend_from_slice(&count.to_be_bytes());
        out
    }

    /// `navigator.credentials.create()` answering creation `options`.
    pub fn create(&mut self, options: &Value, tweak: &Tweak) -> Value {
        if let Some(handle) = options["publicKey"]["user"]["id"].as_str() {
            self.user_handle = Some(unb64(handle));
        }
        let client_data = self.client_data("webauthn.create", options, tweak);
        let count = tweak.sign_count.unwrap_or(self.counter.unwrap_or(0));
        let mut auth_data = self.auth_data_head(self.flags(UP | UV | AT, tweak), count, tweak);
        auth_data.extend_from_slice(&[0x11; 16]);
        let id_len = u16::try_from(self.credential_id.len()).unwrap();
        auth_data.extend_from_slice(&id_len.to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend(tweak.cose_key.clone().unwrap_or_else(|| self.cose_key()));
        // A self-attestation statement: the server must ignore it.
        let att_stmt = Cbor::Map(vec![
            (Cbor::Text("alg".into()), int(-7)),
            (Cbor::Text("sig".into()), Cbor::Bytes(vec![0x30, 0x00])),
        ]);
        let object = cbor(&Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
            (Cbor::Text("attStmt".into()), att_stmt),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]));
        let id = b64(&self.credential_id);
        json!({
            "id": id, "rawId": id, "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "attestationObject": b64(&object),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
        })
    }

    /// `navigator.credentials.get()` answering request `options`.
    pub fn get(&mut self, options: &Value, tweak: &Tweak) -> Value {
        let client_data = self.client_data("webauthn.get", options, tweak);
        let count = match (tweak.sign_count, self.counter) {
            (Some(count), _) => count,
            (None, Some(last)) => {
                self.counter = Some(last + 1);
                last + 1
            }
            (None, None) => 0,
        };
        let auth_data = self.auth_data_head(self.flags(UP | UV, tweak), count, tweak);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(digest(&SHA256, &client_data).as_ref());
        let mut signature = self.sign(&signed);
        if tweak.corrupt_signature {
            let last = signature.len() - 1;
            signature[last] ^= 0x01;
        }
        let handle = match &tweak.user_handle {
            Some(handle) => handle.clone(),
            None => self.user_handle.clone(),
        };
        let id = b64(&self.credential_id);
        json!({
            "id": id, "rawId": id, "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "authenticatorData": b64(&auth_data),
                "signature": b64(&signature),
                "userHandle": handle.map(|h| b64(&h)),
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        })
    }
}
