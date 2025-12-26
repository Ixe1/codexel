use std::path::Path;
use std::path::PathBuf;

use which::which;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub command: String,
    pub args: Vec<String>,
}

#[cfg(windows)]
const PYRIGHT_CANDIDATES: [&str; 3] = [
    "pyright-langserver.cmd",
    "pyright-langserver.exe",
    "pyright-langserver",
];
#[cfg(not(windows))]
const PYRIGHT_CANDIDATES: [&str; 1] = ["pyright-langserver"];

#[cfg(windows)]
const TYPESCRIPT_CANDIDATES: [&str; 3] = [
    "typescript-language-server.cmd",
    "typescript-language-server.exe",
    "typescript-language-server",
];
#[cfg(not(windows))]
const TYPESCRIPT_CANDIDATES: [&str; 1] = ["typescript-language-server"];

fn which_best(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .find_map(|candidate| which(candidate).ok())
}

#[cfg(test)]
fn which_best_in(candidates: &[&str], path_list: &std::ffi::OsStr, cwd: &Path) -> Option<PathBuf> {
    candidates
        .iter()
        .find_map(|candidate| which::which_in(candidate, Some(path_list), cwd).ok())
}

pub(crate) fn autodetect_server(language_id: &str) -> Option<ServerConfig> {
    match language_id {
        "rust" => which_best(&["rust-analyzer", "rust-analyzer.exe"]).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: Vec::new(),
        }),
        "go" => which_best(&["gopls", "gopls.exe"]).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: Vec::new(),
        }),
        "python" => which_best(&PYRIGHT_CANDIDATES).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: vec!["--stdio".to_string()],
        }),
        "typescript" | "javascript" | "typescriptreact" | "javascriptreact" => {
            which_best(&TYPESCRIPT_CANDIDATES).map(|path| ServerConfig {
                command: path.to_string_lossy().to_string(),
                args: vec!["--stdio".to_string()],
            })
        }
        _ => None,
    }
}

pub(crate) fn language_id_for_path(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    match ext.as_str() {
        "rs" => Some("rust"),
        "go" => Some("go"),
        "py" => Some("python"),
        "ts" => Some("typescript"),
        "tsx" => Some("typescriptreact"),
        "js" => Some("javascript"),
        "jsx" => Some("javascriptreact"),
        "json" => Some("json"),
        "toml" => Some("toml"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use pretty_assertions::assert_eq;

    use super::which_best_in;

    fn unique_temp_dir() -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("codex-lsp-which-test-{}-{now}", std::process::id()))
    }

    #[cfg(unix)]
    fn make_executable(path: &std::path::Path) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    #[cfg(windows)]
    fn path_list_for(dir: &std::path::Path) -> OsString {
        OsString::from(dir)
    }

    #[cfg(unix)]
    fn path_list_for(dir: &std::path::Path) -> OsString {
        OsString::from(dir)
    }

    #[cfg(windows)]
    #[test]
    fn which_best_prefers_cmd_over_bare() -> anyhow::Result<()> {
        // `npm` commonly creates `.cmd` shims on Windows; ensure we prefer those.
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir)?;

        let cmd = dir.join("typescript-language-server.cmd");
        let bare = dir.join("typescript-language-server");
        fs::write(&cmd, "@echo off\r\necho ok\r\n")?;
        fs::write(&bare, "not used")?;

        let best = which_best_in(
            &[
                "typescript-language-server.cmd",
                "typescript-language-server",
            ],
            &path_list_for(&dir),
            &dir,
        )
        .unwrap();
        assert_eq!(best, cmd);

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn which_best_finds_executable_in_custom_path() -> anyhow::Result<()> {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir)?;

        let server = dir.join("typescript-language-server");
        fs::write(&server, "#!/bin/sh\nexit 0\n")?;
        make_executable(&server)?;

        let found =
            which_best_in(&["typescript-language-server"], &path_list_for(&dir), &dir).unwrap();
        assert_eq!(found, server);

        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
