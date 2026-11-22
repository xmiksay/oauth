//! Caller-supplied client secrets (`POST …/secrets` with `"secret"`). They
//! are stored as a plain (unsalted) SHA-256 like generated ones, so only an
//! encoding of random bytes may stand in for a generated value: base64,
//! base64url or hex of at least 32 bytes. The server can't prove a value is
//! random; the checks below reject the predictable shapes a human or a
//! template produces when it picks a "strong looking" string instead
//! (repeated units, alphabet runs, small alphabets, words with punctuation).

use base64::{
    Engine,
    engine::general_purpose::{STANDARD_PAD_INDIFFERENT, URL_SAFE_PAD_INDIFFERENT},
};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

pub const MAX_LEN: usize = 256;
/// What the server generates, and what the docs promise: 256 bits.
pub const MIN_BYTES: usize = 32;
pub const MIN_BITS: f64 = 128.0;
/// Ascending / descending character runs this long (`abcdefgh`, `98765432`)
/// are rejected; a random value has one with probability below 1e-6.
const MAX_RUN: usize = 8;

const FORMAT: &str = "secret must be base64, base64url or hex encoding of at least 32 random \
     bytes (e.g. `openssl rand -base64 32`)";

/// Estimated entropy in bits: the length times the Shannon entropy of the
/// value's own character distribution. Blind to order (the period and run
/// checks cover that), it rejects small-alphabet and skewed values.
pub fn estimated_bits(value: &str) -> f64 {
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

/// The bytes `value` encodes: hex when it is an even number of hex digits,
/// else base64 or base64url (padding optional, alphabets not mixed).
pub fn decode(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    if value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return decode_hex(value);
    }
    STANDARD_PAD_INDIFFERENT
        .decode(value)
        .or_else(|_| URL_SAFE_PAD_INDIFFERENT.decode(value))
        .ok()
        .map(Zeroizing::new)
}

fn decode_hex(value: &str) -> Option<Zeroizing<Vec<u8>>> {
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

/// The shortest `p` with `bytes[i] == bytes[i + p]` for every `i`: the length
/// of the unit `bytes` repeats (`bytes.len()` when it repeats nothing).
pub fn shortest_period(bytes: &[u8]) -> usize {
    (1..bytes.len())
        .find(|&p| bytes.iter().zip(bytes.iter().skip(p)).all(|(a, b)| a == b))
        .unwrap_or(bytes.len())
}

/// The longest run of characters each one above (or each one below) the
/// previous: `xabcdy` → 4.
pub fn longest_sequential_run(value: &str) -> usize {
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

/// 400 unless `value` is base64 / base64url / hex of at least 32 bytes that
/// don't repeat a shorter unit, with no long alphabet run and at least 128
/// estimated bits. The message never contains the value.
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
    if shortest_period(&bytes) <= bytes.len() / 2
        || longest_sequential_run(value) >= MAX_RUN
        || estimated_bits(value) < MIN_BITS
    {
        return Err(AppError::BadRequest(
            "secret is too predictable: use random bytes (e.g. `openssl rand -base64 32`)".into(),
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
        // Valid base64 of 48 bytes, but with a 6-byte period.
        let decoded = decode(&password).unwrap();
        assert_eq!((decoded.len(), shortest_period(&decoded)), (48, 6));
        // Longer variants that decode to 32+ bytes are still caught.
        let long_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        assert!(decode(long_alphabet).unwrap().len() >= MIN_BYTES);
        assert!(validate(long_alphabet).is_err());
        let hex_run = "0123456789abcdef".repeat(4);
        assert!(validate(&hex_run).is_err());
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
    fn periods_and_runs() {
        assert_eq!(shortest_period(b""), 0);
        assert_eq!(shortest_period(b"aaaa"), 1);
        assert_eq!(shortest_period(b"abcabcab"), 3);
        assert_eq!(shortest_period(b"abcd"), 4);
        assert_eq!(longest_sequential_run(""), 0);
        assert_eq!(longest_sequential_run("z"), 1);
        assert_eq!(longest_sequential_run("xabcdy"), 4);
        assert_eq!(longest_sequential_run("q98765r"), 5);
    }

    #[test]
    fn hex_decodes_either_case() {
        assert_eq!(decode("00ffA0").unwrap().as_slice(), &[0x00, 0xff, 0xa0]);
    }
}
