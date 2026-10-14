//! Authenticator data (WebAuthn §6.1): rpIdHash ‖ flags ‖ signCount ‖
//! [attested credential data] ‖ [extensions].

use aws_lc_rs::digest::{SHA256, digest};

use super::{MAX_CREDENTIAL_ID, WebauthnError, cbor};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Flags {
    pub const UP: u8 = 0x01;
    pub const UV: u8 = 0x04;
    pub const BE: u8 = 0x08;
    pub const BS: u8 = 0x10;
    pub const AT: u8 = 0x40;
    pub const ED: u8 = 0x80;

    fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
    pub fn user_present(self) -> bool {
        self.has(Self::UP)
    }
    pub fn user_verified(self) -> bool {
        self.has(Self::UV)
    }
    pub fn backup_eligible(self) -> bool {
        self.has(Self::BE)
    }
    pub fn backup_state(self) -> bool {
        self.has(Self::BS)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// The COSE_Key, as encoded by the authenticator.
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: Flags,
    pub sign_count: u32,
    pub attested: Option<AttestedCredential>,
}

const MALFORMED: WebauthnError = WebauthnError::Malformed("authenticator data");

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], WebauthnError> {
    let (head, tail) = input.split_at_checked(n).ok_or(MALFORMED)?;
    *input = tail;
    Ok(head)
}

fn array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], WebauthnError> {
    take(input, N)?.try_into().map_err(|_| MALFORMED)
}

pub fn parse(input: &[u8]) -> Result<AuthData, WebauthnError> {
    let mut rest = input;
    let rp_id_hash = array::<32>(&mut rest)?;
    let [flag_byte] = array::<1>(&mut rest)?;
    let flags = Flags(flag_byte);
    let sign_count = u32::from_be_bytes(array::<4>(&mut rest)?);
    let attested = if flags.has(Flags::AT) {
        let aaguid = array::<16>(&mut rest)?;
        let id_len = usize::from(u16::from_be_bytes(array::<2>(&mut rest)?));
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID {
            return Err(MALFORMED);
        }
        let credential_id = take(&mut rest, id_len)?.to_vec();
        let (key, used) = cbor::decode_prefix(rest, "credential public key")?;
        cbor::map(&key, "credential public key")?;
        let public_key = take(&mut rest, used)?.to_vec();
        Some(AttestedCredential {
            aaguid,
            credential_id,
            public_key,
        })
    } else {
        None
    };
    if flags.has(Flags::ED) {
        let (extensions, used) = cbor::decode_prefix(rest, "extensions")?;
        extensions.as_map().ok_or(MALFORMED)?;
        take(&mut rest, used)?;
    }
    if !rest.is_empty() {
        return Err(MALFORMED);
    }
    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

impl AuthData {
    /// The checks every ceremony shares: right RP, user present AND
    /// verified, and a coherent backup state.
    pub fn check(&self, rp_id: &str) -> Result<(), WebauthnError> {
        if digest(&SHA256, rp_id.as_bytes()).as_ref() != self.rp_id_hash {
            return Err(WebauthnError::WrongRpId);
        }
        if !self.flags.user_present() {
            return Err(WebauthnError::UserNotPresent);
        }
        if !self.flags.user_verified() {
            return Err(WebauthnError::UserNotVerified);
        }
        if self.flags.backup_state() && !self.flags.backup_eligible() {
            return Err(WebauthnError::BackupState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u8, count: u32) -> Vec<u8> {
        let mut out = digest(&SHA256, b"example.org").as_ref().to_vec();
        out.push(flags);
        out.extend_from_slice(&count.to_be_bytes());
        out
    }

    #[test]
    fn minimal_assertion_data() {
        let data = parse(&header(Flags::UP | Flags::UV, 7)).unwrap();
        assert_eq!(data.sign_count, 7);
        assert!(data.attested.is_none());
        assert!(data.check("example.org").is_ok());
        assert_eq!(data.check("example.com"), Err(WebauthnError::WrongRpId));
    }

    #[test]
    fn flag_policy() {
        let check = |flags| parse(&header(flags, 0)).unwrap().check("example.org");
        assert_eq!(check(Flags::UV), Err(WebauthnError::UserNotPresent));
        assert_eq!(check(Flags::UP), Err(WebauthnError::UserNotVerified));
        let bs_only = Flags::UP | Flags::UV | Flags::BS;
        assert_eq!(check(bs_only), Err(WebauthnError::BackupState));
        assert!(check(bs_only | Flags::BE).is_ok());
    }

    #[test]
    fn attested_credential_and_extensions() {
        let mut data = header(Flags::UP | Flags::UV | Flags::AT | Flags::ED, 0);
        data.extend_from_slice(&[9; 16]);
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&[1, 2, 3]);
        data.extend_from_slice(&[0xa1, 0x01, 0x02]); // {1: 2}
        data.extend_from_slice(&[0xa0]); // extensions {}
        let parsed = parse(&data).unwrap();
        let cred = parsed.attested.unwrap();
        assert_eq!(cred.aaguid, [9; 16]);
        assert_eq!(cred.credential_id, vec![1, 2, 3]);
        assert_eq!(cred.public_key, vec![0xa1, 0x01, 0x02]);
        // Trailing garbage, missing extensions, zero-length id.
        let mut trailing = data.clone();
        trailing.push(0);
        assert_eq!(parse(&trailing), Err(MALFORMED));
        assert!(parse(&data[..data.len() - 1]).is_err());
        let mut empty_id = header(Flags::AT, 0);
        empty_id.extend_from_slice(&[0; 18]);
        assert_eq!(parse(&empty_id), Err(MALFORMED));
    }

    #[test]
    fn credential_id_length_is_bounded() {
        let mut data = header(Flags::AT, 0);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&1024u16.to_be_bytes());
        data.extend_from_slice(&[0; 1024]);
        data.extend_from_slice(&[0xa0]);
        assert_eq!(parse(&data), Err(MALFORMED));
    }

    #[test]
    fn truncations_never_panic() {
        let mut data = header(Flags::UP | Flags::UV | Flags::AT, 1);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&[5, 6, 0xa1, 0x01, 0x02]);
        assert!(parse(&data).is_ok());
        for len in 0..data.len() {
            assert!(parse(&data[..len]).is_err(), "prefix {len}");
        }
    }
}
