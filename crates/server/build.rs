//! Bakes the git commit into the binary as `OAUTH_GIT_COMMIT` (`build_info`):
//! `GIT_SHA` (CI passes `github.sha` as a docker build arg, the image has no
//! `.git`), else `git rev-parse` of the checkout, else `unknown`.

#[path = "build/git.rs"]
mod git;

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let dir = Path::new(&dir);
    // Rebuild when HEAD moves; see `git::watched` for which files say so.
    for path in git::watched(dir) {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let from_env = std::env::var("GIT_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let commit = match from_env {
        Some(sha) => git::short(&sha).unwrap_or_else(|| {
            println!("cargo:warning=GIT_SHA is not a hex commit id; ignoring it");
            git::commit(dir)
        }),
        None => git::commit(dir),
    };
    println!("cargo:rustc-env=OAUTH_GIT_COMMIT={commit}");
}
