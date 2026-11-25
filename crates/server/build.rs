//! Bakes the git commit into the binary as `OAUTH_GIT_COMMIT` (`build_info`):
//! `GIT_SHA` (CI passes `github.sha` as a docker build arg, the image has no
//! `.git`), else `git rev-parse` of the checkout, else `unknown`.

use std::{path::Path, process::Command};

/// Short commits are this many hex digits, whichever source they came from.
const SHORT: usize = 12;

fn main() {
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let dir = Path::new(&dir);
    watch_head(dir);

    let from_env = std::env::var("GIT_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let commit = match from_env {
        Some(sha) => short(&sha).unwrap_or_else(|| {
            println!("cargo:warning=GIT_SHA is not a hex commit id; ignoring it");
            from_git(dir)
        }),
        None => from_git(dir),
    };
    println!("cargo:rustc-env=OAUTH_GIT_COMMIT={commit}");
}

/// The first `SHORT` digits of a hex commit id (at least that long),
/// lowercased. `None` for anything else, so nothing but `[0-9a-f]` ever
/// reaches the binary (it ends up in a metric label and the SPA's HTML).
fn short(sha: &str) -> Option<String> {
    let sha = sha.trim();
    let valid = sha.len() >= SHORT && sha.chars().all(|c| c.is_ascii_hexdigit());
    valid.then(|| {
        sha.chars()
            .take(SHORT)
            .collect::<String>()
            .to_ascii_lowercase()
    })
}

fn from_git(dir: &Path) -> String {
    git(dir, &["rev-parse", &format!("--short={SHORT}"), "HEAD"])
        .and_then(|sha| short(&sha))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Rebuild when HEAD moves: `HEAD` itself (checkout), the branch it points
/// at (commit) and `packed-refs` (where git may keep that branch). Paths
/// come from git, so linked worktrees (where `.git` is a file) work too. Only
/// existing files are watched: cargo reruns the script on every build for a
/// missing one.
fn watch_head(dir: &Path) {
    let mut refs = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    if let Some(branch) = git(dir, &["symbolic-ref", "-q", "HEAD"]) {
        refs.push(branch);
    }
    for name in refs {
        let Some(path) = git(dir, &["rev-parse", "--git-path", &name]) else {
            continue;
        };
        let path = dir.join(path);
        if path.is_file() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// Trimmed stdout of a successful `git` call in `dir`.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (out.status.success() && !text.is_empty()).then(|| text.to_owned())
}
