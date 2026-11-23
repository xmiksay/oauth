//! Caller-supplied client secrets (`POST …/secrets` with `"secret"`). They
//! are stored as a plain (unsalted) SHA-256 like generated ones, so only an
//! encoding of random bytes may stand in for a generated value: base64,
//! base64url or hex of at least 32 bytes. The server can't prove a value is
//! random; the checks below only reject obviously predictable shapes
//! (repeated substrings, alphabet runs, sequential bytes, small or skewed
//! alphabets). They cannot detect words or a passphrase that repeats nothing
//! and happens to be valid base64
//! (`MyAcmeCorpProductionOauthClientSecretKey2026` passes), so the value must
//! come from a CSPRNG (`openssl rand -base64 32`); the docs and error
//! messages say so.
//! Repetition is any substring occurring twice, not only a whole-value
//! period: a repeated word followed by a short random tail has no period but
//! still repeats its word. It is looked for twice: as a repeated 4-byte
//! window in the decoded bytes, and as a repeated 7-character (8 for hex)
//! window in the text with ASCII case folded, because base64 maps 4
//! characters to 3 bytes and so hides a repeated word whose length isn't a
//! multiple of 4 (`"password1"` × 5 repeats no byte window at offset 9).
//! Window sizes keep a random value's false-reject chance below ~1e-5 even
//! at the 256-character maximum (about 1e-6 for 32 bytes).
//! Sequences are looked for in both forms too: an alphabet run in the text
//! (`abcdefgh`), and an arithmetic progression in the decoded bytes (bytes
//! 0..31, every second byte, ASCII `A`..), which an encoding turns into
//! text with no character run (`000102…`, `AAECAwQF…`).

use std::collections::HashSet;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD_PAD_INDIFFERENT, URL_SAFE_PAD_INDIFFERENT},
};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

const MAX_LEN: usize = 256;
/// What the server generates, and what the docs promise: 256 bits.
const MIN_BYTES: usize = 32;
const MIN_BITS: f64 = 128.0;
/// Ascending / descending character runs this long (`abcdefgh`, `98765432`)
/// are rejected; a random value has one with probability below 1e-6.
const MAX_RUN: usize = 8;
/// Decoded byte runs this long with one constant (wrapping) step are
/// rejected: a random byte starts one with probability 256^-4, so a 192-byte
/// value is falsely rejected with probability about 190 × 256^-4 ≈ 4e-8.
const MAX_BYTE_PROGRESSION: usize = 6;
/// Repeated-window lengths (see the module doc): decoded bytes, case-folded
/// base64 text, case-folded hex text.
const BYTE_WINDOW: usize = 4;
const BASE64_TEXT_WINDOW: usize = 7;
const HEX_TEXT_WINDOW: usize = 8;

const FORMAT: &str = "secret must be base64, base64url or hex encoding of at least 32 random \
     bytes (e.g. `openssl rand -base64 32`)";

/// Estimated entropy in bits: the length times the Shannon entropy of the
/// value's own character distribution. Blind to order (the period and run
/// checks cover that), it rejects small-alphabet and skewed values.
fn estimated_bits(value: &str) -> f64 {
    let mut counts = [0u32; 128];
    let mut n = 0u32;
    for b in value.bytes() {
        if let Some(c) = counts.get_mut(usize::from(b & 0x7f)) {
            *c += 1;
        }
        n += 1;
    }
    let total = f64::from(n);
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| f64::from(c) * (total / f64::from(c)).log2())
        .sum()
}

/// The bytes `value` encodes: hex when it is all hex digits (an odd count is
/// no encoding, not unpadded base64: 43 hex digits would otherwise decode to
/// 32 bytes while carrying only 21.5), else base64 or base64url (padding
/// optional, alphabets not mixed).
fn decode(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    if is_hex(value) {
        return decode_hex(value);
    }
    STANDARD_PAD_INDIFFERENT
        .decode(value)
        .or_else(|_| URL_SAFE_PAD_INDIFFERENT.decode(value))
        .ok()
        .map(Zeroizing::new)
}

fn is_hex(value: &str) -> bool {
    value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode_hex(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let nibbles: Option<Vec<u8>> = value
        .chars()
        .map(|c| c.to_digit(16).and_then(|d| u8::try_from(d).ok()))
        .collect();
    let nibbles = Zeroizing::new(nibbles?);
    Some(Zeroizing::new(
        nibbles
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[hi, lo]| (hi << 4) | lo)
            .collect(),
    ))
}

/// Whether some `window`-long substring of `bytes` occurs twice (overlaps
/// count: `aaaaa` repeats `aaaa`).
fn has_repeated_window(bytes: &[u8], window: usize) -> bool {
    let mut seen = HashSet::new();
    bytes.windows(window).any(|w| !seen.insert(w))
}

/// The longest run of characters each one above (or each one below) the
/// previous: `xabcdy` → 4.
fn longest_sequential_run(value: &str) -> usize {
    let bytes = value.as_bytes();
    let mut longest = usize::from(!bytes.is_empty());
    for step in [1i16, -1] {
        let mut run = 1;
        for pair in bytes.windows(2) {
            if let [a, b] = pair
                && i16::from(*b) - i16::from(*a) == step
            {
                run += 1;
                longest = longest.max(run);
            } else {
                run = 1;
            }
        }
    }
    longest
}

/// The longest run of bytes with one constant wrapping step between
/// neighbours (`00 02 04 06` → 4; any step, including 0).
fn longest_byte_progression(bytes: &[u8]) -> usize {
    let mut longest = bytes.len().min(2);
    let mut run = longest;
    for triple in bytes.windows(3) {
        if let [a, b, c] = triple
            && b.wrapping_sub(*a) == c.wrapping_sub(*b)
        {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 2;
        }
    }
    longest
}

/// Whether the decoded bytes or the case-folded text repeat a substring.
fn repeats(value: &str, bytes: &[u8]) -> bool {
    let folded = Zeroizing::new(value.to_ascii_lowercase());
    let text_window = if is_hex(value) {
        HEX_TEXT_WINDOW
    } else {
        BASE64_TEXT_WINDOW
    };
    has_repeated_window(bytes, BYTE_WINDOW) || has_repeated_window(folded.as_bytes(), text_window)
}

/// 400 unless `value` is base64 / base64url / hex of at least 32 bytes,
/// neither those bytes nor the case-folded text repeat a substring, with no
/// long alphabet run in the text, no long arithmetic progression in the
/// bytes and at least 128 estimated bits. The message never
/// contains the value.
pub fn validate(value: &str) -> AppResult<()> {
    if value.len() > MAX_LEN {
        return Err(AppError::BadRequest(format!(
            "secret must be at most {MAX_LEN} characters"
        )));
    }
    let bytes = decode(value).ok_or_else(|| AppError::BadRequest(FORMAT.into()))?;
    if bytes.len() < MIN_BYTES {
        return Err(AppError::BadRequest(FORMAT.into()));
    }
    if repeats(value, &bytes)
        || longest_sequential_run(value) >= MAX_RUN
        || longest_byte_progression(&bytes) >= MAX_BYTE_PROGRESSION
        || estimated_bits(value) < MIN_BITS
    {
        return Err(AppError::BadRequest(
            "secret has a predictable shape (repeats, sequences or low variety): \
             generate it with a CSPRNG (e.g. `openssl rand -base64 32`)"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret;

    #[test]
    fn generated_values_pass() {
        for _ in 0..200 {
            let token = secret::random_token().unwrap();
            assert!(validate(&token).is_ok(), "{token}");
        }
        for value in [
            "e83239adaf4444a9ae61ba14223b320a31e6ade2f006e2170651faff226e8718",
            "E83239ADAF4444A9AE61BA14223B320A31E6ADE2F006E2170651FAFF226E8718",
            "2fWH6CRxNI9OZg3nSFittXX4ugYKS+tHSKM8+Qqf7/I=",
            "2fWH6CRxNI9OZg3nSFittXX4ugYKS+tHSKM8+Qqf7/I",
            "mZOWZylKwwVXXPmCV9rrSl3slrjp2bjUIQyc79qbsFo",
            "mZOWZylKwwVXXPmCV9rrSl3slrjp2bjUIQyc79qbsFo=",
        ] {
            assert!(validate(value).is_ok(), "{value}");
        }
    }

    #[test]
    fn issue_81_examples_fail() {
        let password = "password".repeat(8);
        let alphabet = "abcdefghijklmnopqrstuvwxyz012345";
        let company = "CompanyNameProductionSecret2026!";
        // Each passed the old character-histogram estimate alone.
        for value in [password.as_str(), alphabet, company] {
            assert!(estimated_bits(value) >= MIN_BITS, "{value}");
            assert!(validate(value).is_err(), "{value}");
        }
        // Valid base64 of 48 bytes, but repeating every 6 bytes.
        let decoded = decode(&password).unwrap();
        assert_eq!(decoded.len(), 48);
        assert!(has_repeated_window(&decoded, BYTE_WINDOW));
        // Longer variants that decode to 32+ bytes are still caught.
        let long_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        assert!(decode(long_alphabet).unwrap().len() >= MIN_BYTES);
        assert!(validate(long_alphabet).is_err());
        let hex_run = "0123456789abcdef".repeat(4);
        assert!(validate(&hex_run).is_err());
    }

    #[test]
    fn repeated_words_fail_whatever_follows_them() {
        let probes = [
            format!("{}pas", "password1".repeat(5)),
            "passwordpassword1".repeat(4),
            // #81 review: a short tail leaves no whole-value period.
            format!("{}AbCd", "password".repeat(5)),
            format!("{}Xq9z", "MyCompanySecretKey2026".repeat(2)),
            "MyCompanySecretKey2026".repeat(2),
            // Case changes don't hide the repetition.
            format!("{}{}", "MyCompanySecretKey2026", "mycompanysecretkey2026"),
        ];
        for value in &probes {
            // Valid base64 of 32+ bytes, enough estimated bits and no long
            // run: only the repetition check catches them.
            let bytes = decode(value).unwrap();
            assert!(bytes.len() >= MIN_BYTES, "{value}");
            assert!(estimated_bits(value) >= MIN_BITS, "{value}");
            assert!(longest_sequential_run(value) < MAX_RUN, "{value}");
            assert!(repeats(value, &bytes), "{value}");
            assert!(validate(value).is_err(), "{value}");
        }
        // A word repeated off the 4-character grid repeats no byte window:
        // the case-folded text check is what finds it.
        let company = format!("{}Xq9z", "MyCompanySecretKey2026".repeat(2));
        assert!(!has_repeated_window(
            &decode(&company).unwrap(),
            BYTE_WINDOW
        ));
    }

    #[test]
    fn non_repeating_words_pass_a_known_limit() {
        // #81 review: a word-built value that is valid base64 of 32+ bytes and
        // repeats nothing passes. The checks reject predictable shapes, not
        // human choice; the docs require a CSPRNG for exactly this reason.
        let phrase = "MyAcmeCorpProductionOauthClientSecretKey2026";
        assert!(decode(phrase).unwrap().len() >= MIN_BYTES);
        assert!(validate(phrase).is_ok());
    }

    #[test]
    fn weak_values_fail() {
        let hex32 = "9f86d081884c7d659a2feaa0c55ad015";
        let base64_24_bytes = "2fWH6CRxNI9OZg3nSFittXX4ugYKS+tH";
        let mixed_alphabets = "2fWH6CRxNI9OZg3nSFittXX4ugYKS+tHSKM8-Qqf7_I";
        let repetitive = "a".repeat(64);
        let two_letters = "ab".repeat(40);
        let skewed = format!("{}b", "0".repeat(63));
        let spaced = format!("{} x", secret::random_token().unwrap());
        let too_long = "A".repeat(MAX_LEN + 4);
        for value in [
            "Ab3$Ab3$Ab3$",
            hex32,
            base64_24_bytes,
            mixed_alphabets,
            &repetitive,
            &two_letters,
            &skewed,
            &spaced,
            &too_long,
            &"é".repeat(40),
        ] {
            let err = validate(value).unwrap_err();
            // The value itself never appears in the error.
            assert!(!format!("{err:?}").contains(value), "{value}");
        }
        assert_eq!(estimated_bits(&repetitive), 0.0);
        assert!((estimated_bits(&two_letters) - 80.0).abs() < 1e-9);
    }

    #[test]
    fn windows_and_runs() {
        assert!(!has_repeated_window(b"", 4));
        assert!(!has_repeated_window(b"abc", 4));
        assert!(has_repeated_window(b"aaaaa", 4));
        assert!(has_repeated_window(b"xabcdyabcdz", 4));
        assert!(!has_repeated_window(b"xabcdyabcez", 4));
        // Hex text gets the longer window: 7 repeated hex digits are fine.
        // (`5e59485` occurs twice, at an odd offset.)
        let hex = "5e59485c1bab61984690ba25a4682f511363b54b75e59485f25679b8104eb547";
        assert!(is_hex(hex) && !repeats(hex, &decode(hex).unwrap()));
        assert!(validate(hex).is_ok());
        assert_eq!(longest_sequential_run(""), 0);
        assert_eq!(longest_sequential_run("z"), 1);
        assert_eq!(longest_sequential_run("xabcdy"), 4);
        assert_eq!(longest_sequential_run("q98765r"), 5);
    }

    #[test]
    fn sequential_bytes_fail_in_any_encoding() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        let ascending: Vec<u8> = (0..32).collect();
        let evens: Vec<u8> = (0..64).step_by(2).collect();
        let printable: Vec<u8> = (32..64).collect();
        let letters: Vec<u8> = (b'A'..=b'`').collect();
        let descending: Vec<u8> = (0..40u8).map(|i| 200 - 3 * i).collect();
        let mut probes = Vec::new();
        for bytes in [&ascending, &evens, &printable, &letters, &descending] {
            probes.push(hex(bytes));
            probes.push(STANDARD.encode(bytes));
            probes.push(URL_SAFE_NO_PAD.encode(bytes));
        }
        // #81 review: the usual base64 test vector of bytes 0..31.
        assert!(probes.contains(&"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_owned()));
        assert!(probes.contains(
            &"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_owned()
        ));
        for value in &probes {
            let bytes = decode(value).unwrap();
            assert!(bytes.len() >= MIN_BYTES, "{value}");
            assert!(
                longest_byte_progression(&bytes) >= MAX_BYTE_PROGRESSION,
                "{value}"
            );
            assert!(validate(value).is_err(), "{value}");
        }
        // Only the byte check catches these: the text neither repeats nor runs.
        for bytes in [&ascending, &evens] {
            for value in [hex(bytes), STANDARD.encode(bytes)] {
                let decoded = decode(&value).unwrap();
                assert!(!repeats(&value, &decoded), "{value}");
                assert!(longest_sequential_run(&value) < MAX_RUN, "{value}");
                assert!(estimated_bits(&value) >= MIN_BITS, "{value}");
            }
        }
    }

    #[test]
    fn byte_progressions() {
        assert_eq!(longest_byte_progression(&[]), 0);
        assert_eq!(longest_byte_progression(&[7]), 1);
        assert_eq!(longest_byte_progression(&[7, 200]), 2);
        assert_eq!(longest_byte_progression(&[9, 0, 2, 4, 6, 1]), 4);
        // Wrapping: 0xfe, 0xff, 0x00, 0x01 is one step of +1.
        assert_eq!(longest_byte_progression(&[0xfe, 0xff, 0x00, 0x01, 0x50]), 4);
        assert_eq!(longest_byte_progression(&[5, 5, 5, 5, 5, 5]), 6);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hex_decodes_either_case() {
        assert_eq!(decode("00ffA0").unwrap().as_slice(), &[0x00, 0xff, 0xa0]);
        // An odd count of hex digits is malformed hex, never unpadded base64.
        let odd = &"5e59485c1bab61984690ba25a4682f511363b54b75e59485f25679b8104eb547"[..43];
        assert!(decode(odd).is_none());
        assert!(validate(odd).is_err());
    }
}
