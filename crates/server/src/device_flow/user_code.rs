//! User codes (RFC 8628 §6.1): 8 characters from 20 consonants — no vowels
//! (no words), no digits and none of the look-alikes `0 O 1 I` — about 34.5
//! bits, shown as `XXXX-XXXX`. What a user types is normalised: case,
//! dashes and whitespace don't matter.

use crate::secret;

pub const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
pub const LEN: usize = 8;
/// Longer input is rejected before it is looked at further.
const MAX_INPUT: usize = 64;

/// A fresh code in normalised form (no dash).
pub fn generate() -> anyhow::Result<String> {
    secret::random_string(ALPHABET, LEN)
}

/// `BCDFGHJK` → `BCDF-GHJK`.
pub fn display(code: &str) -> String {
    match (code.get(..LEN / 2), code.get(LEN / 2..)) {
        (Some(head), Some(tail)) => format!("{head}-{tail}"),
        _ => code.to_owned(),
    }
}

/// The normalised code, or `None` when `input` can't be a user code.
pub fn normalize(input: &str) -> Option<String> {
    if input.len() > MAX_INPUT {
        return None;
    }
    let code: String = input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let valid = code.len() == LEN && code.bytes().all(|b| ALPHABET.contains(&b));
    valid.then_some(code)
}

/// Storage hash of a normalised code.
pub fn hash(code: &str) -> Vec<u8> {
    secret::hash(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_use_the_alphabet() {
        for _ in 0..100 {
            let code = generate().unwrap();
            assert_eq!(normalize(&code), Some(code.clone()));
            let shown = display(&code);
            assert_eq!(shown.len(), LEN + 1);
            assert_eq!(&shown[4..5], "-");
            assert_eq!(normalize(&shown), Some(code));
        }
    }

    #[test]
    fn alphabet_has_no_vowels_digits_or_look_alikes() {
        assert_eq!(ALPHABET.len(), 20);
        for b in b"AEIOUY0123456789" {
            assert!(!ALPHABET.contains(b), "{}", char::from(*b));
        }
    }

    #[test]
    fn normalises_typed_input() {
        let want = Some("BCDFGHJK".to_owned());
        assert_eq!(normalize("bcdf-ghjk"), want);
        assert_eq!(normalize(" BCDF GHJK "), want);
        assert_eq!(normalize("BCDFGHJK"), want);
        assert_eq!(normalize("BC-DF-GH-JK"), want);
    }

    #[test]
    fn rejects_what_cant_be_a_code() {
        for bad in [
            "",
            "BCDF-GHJ",
            "BCDF-GHJKL",
            "ABCD-EFGH",
            "BCDF-GHJ1",
            "BCDF-GHJ\u{e9}",
        ] {
            assert_eq!(normalize(bad), None, "{bad}");
        }
        assert_eq!(normalize(&"-".repeat(65)), None);
    }
}
