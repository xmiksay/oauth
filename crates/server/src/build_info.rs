//! What this binary was built from: the workspace version and the git commit
//! `build.rs` baked in (`GIT_SHA`, else `git rev-parse`, else `unknown`).
//! Reported by `oauth --version`, the `serve` startup log, the
//! `oauth_build_info` metric and the SPA's `oauth-build` `<meta>`.

/// The workspace version (`Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The short (12 hex digit) commit, or `unknown`. `build.rs` lets nothing
/// else through.
pub const COMMIT: &str = env!("OAUTH_GIT_COMMIT");

/// `<version> (<commit>)`, as `oauth --version` prints it.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("OAUTH_GIT_COMMIT"),
    ")"
);

// `build.rs`'s git helpers, compiled here only so their tests run.
#[cfg(test)]
#[path = "../build/git.rs"]
mod build_git;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_version_is_version_then_commit() {
        assert_eq!(LONG_VERSION, format!("{VERSION} ({COMMIT})"));
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn commit_is_short_hex_or_unknown() {
        assert!(
            COMMIT == "unknown"
                || (COMMIT.len() == 12
                    && COMMIT
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "{COMMIT}"
        );
    }
}
