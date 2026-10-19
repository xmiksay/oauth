//! Bounding upstream profile claims before they reach the database or a
//! login transaction: the provider is not trusted to send sane text.

const MAX_NAME_CHARS: usize = 256;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_TOKEN_BYTES: usize = 256;

/// Control characters (NUL included) removed, whitespace trimmed, at most
/// 256 characters; `None` when nothing is left.
pub fn clean_name(raw: &str) -> Option<String> {
    let stripped: String = raw.chars().filter(|c| !c.is_control()).collect();
    let name: String = stripped.trim().chars().take(MAX_NAME_CHARS).collect();
    let name = name.trim_end().to_owned();
    (!name.is_empty()).then_some(name)
}

/// An email as given, if it is 1–320 bytes without control characters.
pub fn clean_email(raw: &str) -> Option<String> {
    let ok = (1..=MAX_EMAIL_BYTES).contains(&raw.len()) && !raw.chars().any(char::is_control);
    ok.then(|| raw.to_owned())
}

/// A short opaque value (`amr` entry, `acr`): 1–256 bytes, no controls.
pub fn clean_token(raw: &str) -> Option<String> {
    let ok = (1..=MAX_TOKEN_BYTES).contains(&raw.len()) && !raw.chars().any(char::is_control);
    ok.then(|| raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(
            clean_name("  Ann\u{0}  Lee \n").as_deref(),
            Some("Ann  Lee")
        );
        assert_eq!(clean_name("\u{0}\u{7}"), None);
        assert_eq!(clean_name(&"x".repeat(1000)).unwrap().len(), 256);
    }

    #[test]
    fn emails_and_tokens() {
        assert_eq!(clean_email("a@b").as_deref(), Some("a@b"));
        assert_eq!(clean_email("a\u{0}@b"), None);
        assert_eq!(clean_email(&"x".repeat(321)), None);
        assert_eq!(clean_email(""), None);
        assert_eq!(clean_token("mfa").as_deref(), Some("mfa"));
        assert_eq!(clean_token(&"x".repeat(257)), None);
    }
}
