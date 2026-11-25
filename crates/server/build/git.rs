//! The git side of `build.rs`, in its own file so the library's unit tests
//! can include it (`build_info`): build scripts have no test harness.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// Short commits are this many hex digits, whichever source they came from.
pub const SHORT: usize = 12;

/// The first `SHORT` digits of a hex commit id (at least that long),
/// lowercased. `None` for anything else, so nothing but `[0-9a-f]` ever
/// reaches the binary (it ends up in a metric label and the SPA's HTML).
pub fn short(sha: &str) -> Option<String> {
    let sha = sha.trim();
    let valid = sha.len() >= SHORT && sha.chars().all(|c| c.is_ascii_hexdigit());
    valid.then(|| {
        sha.chars()
            .take(SHORT)
            .collect::<String>()
            .to_ascii_lowercase()
    })
}

/// `git rev-parse` of HEAD in `dir`, else `unknown`.
pub fn commit(dir: &Path) -> String {
    git(dir, &["rev-parse", &format!("--short={SHORT}"), "HEAD"])
        .and_then(|sha| short(&sha))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// The files whose change means HEAD may have moved, for
/// `cargo:rerun-if-changed`. Paths come from `git rev-parse --git-path`, so
/// linked worktrees (where `.git` is a file) get their own `HEAD` and reflog.
///
/// - `HEAD`: checkout, and every commit on a detached HEAD;
/// - `packed-refs`: where `git gc` / `pack-refs` moves the branch;
/// - `logs/HEAD`: the reflog gets a line on every move of HEAD — commit,
///   fast-forward, reset — even when the branch ref was packed and the move
///   creates a loose ref file that was not there to be watched;
/// - the loose branch ref, when it exists.
///
/// Missing files are left out (cargo reruns the script on every build for a
/// missing one) with one exception: a packed branch in a repository without
/// a reflog (`core.logAllRefUpdates=false`). Nothing existing would change on
/// the next commit, so the path the loose ref will appear at is watched
/// anyway: correct commit over a skipped rerun.
pub fn watched(dir: &Path) -> Vec<PathBuf> {
    let path = |name: &str| git(dir, &["rev-parse", "--git-path", name]).map(|p| dir.join(p));
    let mut out: Vec<PathBuf> = ["HEAD", "packed-refs", "logs/HEAD"]
        .into_iter()
        .filter_map(path)
        .filter(|p| p.is_file())
        .collect();
    let has_reflog = out.iter().any(|p| p.ends_with("logs/HEAD"));
    let branch = git(dir, &["symbolic-ref", "-q", "HEAD"]).and_then(|b| path(&b));
    out.extend(branch.filter(|b| b.is_file() || !has_reflog));
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    fn run(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    /// A repository on `main` with one commit, its branch ref packed.
    fn packed_repo() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        run(dir, &["init", "-q"]);
        run(dir, &["commit", "-q", "--allow-empty", "-m", "one"]);
        run(dir, &["pack-refs", "--all"]);
        assert!(!dir.join(".git/refs/heads/main").exists());
        tmp
    }

    fn names(dir: &Path) -> Vec<String> {
        let git_dir = dir.join(".git");
        watched(dir)
            .iter()
            .map(|p| p.strip_prefix(&git_dir).unwrap().display().to_string())
            .collect()
    }

    #[test]
    fn short_takes_twelve_lowercase_hex_digits() {
        assert_eq!(
            short(" ABCDEF0123456789abcdef \n").as_deref(),
            Some("abcdef012345")
        );
        assert_eq!(short("abc"), None);
        assert_eq!(short("zzzzzzzzzzzzzzzz"), None);
    }

    #[test]
    fn packed_branch_is_covered_by_the_reflog() {
        let tmp = packed_repo();
        let dir = tmp.path();
        assert_eq!(names(dir), ["HEAD", "packed-refs", "logs/HEAD"]);

        // The commit that brings the loose ref back must touch a watched file.
        let reflog = dir.join(".git/logs/HEAD");
        let logged = std::fs::read_to_string(&reflog).unwrap();
        run(dir, &["commit", "-q", "--allow-empty", "-m", "two"]);
        assert_ne!(std::fs::read_to_string(&reflog).unwrap(), logged);
        assert_eq!(commit(dir), short(&head(dir)).unwrap());

        // Now loose again, the branch ref is watched as well.
        assert_eq!(
            names(dir),
            ["HEAD", "packed-refs", "logs/HEAD", "refs/heads/main"]
        );
    }

    #[test]
    fn packed_branch_without_reflog_watches_where_the_ref_will_appear() {
        let tmp = packed_repo();
        let dir = tmp.path();
        run(dir, &["config", "core.logAllRefUpdates", "false"]);
        std::fs::remove_dir_all(dir.join(".git/logs")).unwrap();
        assert_eq!(names(dir), ["HEAD", "packed-refs", "refs/heads/main"]);
    }

    fn head(dir: &Path) -> String {
        git(dir, &["rev-parse", "HEAD"]).unwrap()
    }
}
