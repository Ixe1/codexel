//! Utility to list changed files in the current Git repository.
//!
//! This is a best-effort helper used for improving `/diagnostics`: many LSP
//! servers only report diagnostics for files they have opened.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::Command;

/// Return value of [`get_git_changed_files`].
///
/// * `Option<PathBuf>` â€“ Repo root (if inside a Git repo).
/// * `Vec<PathBuf>` â€“ Absolute file paths for changed files (may be empty).
pub(crate) async fn get_git_changed_files(
    cwd: &Path,
) -> io::Result<(Option<PathBuf>, Vec<PathBuf>)> {
    let Some(repo_root) = git_repo_root(cwd).await? else {
        return Ok((None, Vec::new()));
    };

    let (unstaged_res, staged_res, untracked_res) = tokio::join!(
        run_git_capture_stdout(cwd, &["diff", "--name-only"]),
        run_git_capture_stdout(cwd, &["diff", "--name-only", "--cached"]),
        run_git_capture_stdout(cwd, &["ls-files", "--others", "--exclude-standard"]),
    );

    let mut rel_paths: BTreeSet<String> = BTreeSet::new();
    for out in [unstaged_res?, staged_res?, untracked_res?] {
        for line in out.lines().map(str::trim).filter(|s| !s.is_empty()) {
            rel_paths.insert(line.to_string());
        }
    }

    let mut abs_paths = Vec::with_capacity(rel_paths.len());
    for rel in rel_paths {
        abs_paths.push(repo_root.join(rel));
    }

    Ok((Some(repo_root), abs_paths))
}

async fn git_repo_root(cwd: &Path) -> io::Result<Option<PathBuf>> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await;

    let output = match output {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None), // git not installed
        Err(e) => return Err(e),
    };

    if !output.status.success() {
        return Ok(None);
    }

    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(root)))
}

async fn run_git_capture_stdout(cwd: &Path, args: &[&str]) -> io::Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await;

    let output = match output {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e),
    };

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Ok(String::new())
    }
}
