//! Caller-supplied client secrets (`POST …/secrets` with `"secret"`): only
//! values that are long and varied enough to stand in for a generated one,
//! since they are stored as a plain (unsalted) SHA-256 like generated ones.

use crate::error::{AppError, AppResult};

pub const MIN_LEN: usize = 32;
pub const MAX_LEN: usize = 256;
pub const MIN_BITS: f64 = 128.0;

/// Estimated entropy in bits: the length times the Shannon entropy of the
/// value's own character distribution. It can't see structure (a known
/// phrase passes if its letters are varied enough), but it rejects short,
/// repetitive and small-alphabet values: 64 hex digits pass, 32 don't.
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

/// 400 unless `value` is 32–256 visible ASCII characters with at least 128
/// estimated bits. The message never contains the value.
pub fn validate(value: &str) -> AppResult<()> {
    let len = value.len();
    if !(MIN_LEN..=MAX_LEN).contains(&len) {
        return Err(AppError::BadRequest(format!(
            "secret must be {MIN_LEN}-{MAX_LEN} characters"
        )));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(AppError::BadRequest(
            "secret must be visible ASCII characters (no spaces)".into(),
        ));
    }
    if estimated_bits(value) < MIN_BITS {
        return Err(AppError::BadRequest(format!(
            "secret is too predictable (needs at least {MIN_BITS} bits of estimated entropy; \
             use e.g. 32 random bytes, base64-encoded)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret;

    #[test]
    fn generated_values_pass() {
        for _ in 0..50 {
            let token = secret::random_token().unwrap();
            assert!(validate(&token).is_ok(), "{}", estimated_bits(&token));
        }
        let hex64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert!(validate(hex64).is_ok());
    }

    #[test]
    fn weak_values_fail() {
        let too_short = "Ab3$Ab3$Ab3$";
        let repetitive = "a".repeat(64);
        let two_letters = "ab".repeat(40);
        let hex32 = "9f86d081884c7d659a2feaa0c55ad015";
        let spaced = format!("{} x", secret::random_token().unwrap());
        let too_long = "x".repeat(MAX_LEN + 1);
        for value in [
            too_short,
            &repetitive,
            &two_letters,
            hex32,
            &spaced,
            &too_long,
        ] {
            let err = validate(value).unwrap_err();
            // The value itself never appears in the error.
            assert!(!format!("{err:?}").contains(value));
        }
        assert_eq!(estimated_bits(&repetitive), 0.0);
        assert!((estimated_bits(&two_letters) - 80.0).abs() < 1e-9);
        assert!(validate(&"é".repeat(20)).is_err());
    }
}
