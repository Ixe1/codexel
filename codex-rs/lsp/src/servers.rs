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

#[cfg(windows)]
const INTELEPHENSE_CANDIDATES: [&str; 3] = ["intelephense.cmd", "intelephense.exe", "intelephense"];
#[cfg(not(windows))]
const INTELEPHENSE_CANDIDATES: [&str; 1] = ["intelephense"];

#[cfg(windows)]
const CSHARP_LS_CANDIDATES: [&str; 3] = ["csharp-ls.cmd", "csharp-ls.exe", "csharp-ls"];
#[cfg(not(windows))]
const CSHARP_LS_CANDIDATES: [&str; 1] = ["csharp-ls"];

#[cfg(windows)]
const OMNISHARP_CANDIDATES: [&str; 6] = [
    "OmniSharp.cmd",
    "OmniSharp.exe",
    "OmniSharp",
    "omnisharp.cmd",
    "omnisharp.exe",
    "omnisharp",
];
#[cfg(not(windows))]
const OMNISHARP_CANDIDATES: [&str; 2] = ["omnisharp", "OmniSharp"];

#[cfg(windows)]
const PERL_NAVIGATOR_CANDIDATES: [&str; 6] = [
    "perlnavigator.cmd",
    "perlnavigator.exe",
    "perlnavigator",
    "perl-navigator.cmd",
    "perl-navigator.exe",
    "perl-navigator",
];
#[cfg(not(windows))]
const PERL_NAVIGATOR_CANDIDATES: [&str; 2] = ["perlnavigator", "perl-navigator"];

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

fn autodetect_server_with(
    language_id: &str,
    which_best_fn: impl Fn(&[&str]) -> Option<PathBuf>,
) -> Option<ServerConfig> {
    match language_id {
        "rust" => which_best_fn(&["rust-analyzer", "rust-analyzer.exe"]).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: Vec::new(),
        }),
        "go" => which_best_fn(&["gopls", "gopls.exe"]).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: Vec::new(),
        }),
        "python" => which_best_fn(&PYRIGHT_CANDIDATES).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: vec!["--stdio".to_string()],
        }),
        "typescript" | "javascript" | "typescriptreact" | "javascriptreact" => {
            which_best_fn(&TYPESCRIPT_CANDIDATES).map(|path| ServerConfig {
                command: path.to_string_lossy().to_string(),
                args: vec!["--stdio".to_string()],
            })
        }
        "php" => which_best_fn(&INTELEPHENSE_CANDIDATES).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: vec!["--stdio".to_string()],
        }),
        "csharp" => which_best_fn(&CSHARP_LS_CANDIDATES)
            .map(|path| ServerConfig {
                command: path.to_string_lossy().to_string(),
                args: vec!["--stdio".to_string()],
            })
            .or_else(|| {
                which_best_fn(&OMNISHARP_CANDIDATES).map(|path| ServerConfig {
                    command: path.to_string_lossy().to_string(),
                    args: vec!["--languageserver".to_string()],
                })
            }),
        "perl" => which_best_fn(&PERL_NAVIGATOR_CANDIDATES).map(|path| ServerConfig {
            command: path.to_string_lossy().to_string(),
            args: Vec::new(),
        }),
        _ => None,
    }
}

pub(crate) fn autodetect_server(language_id: &str) -> Option<ServerConfig> {
    autodetect_server_with(language_id, which_best)
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
        "php" | "phtml" | "php5" | "php7" | "phps" => Some("php"),
        "cs" | "csproj" | "sln" => Some("csharp"),
        "pl" | "pm" | "t" | "psgi" => Some("perl"),
        "json" => Some("json"),
        "toml" => Some("toml"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use pretty_assertions::assert_eq;

    use super::ServerConfig;
    use super::autodetect_server_with;
    use super::language_id_for_path;
    use super::which_best_in;

    fn unique_temp_dir() -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        std::env::temp_dir().join(format!("codex-lsp-which-test-{pid}-{now}"))
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

    #[test]
    fn language_id_for_path_includes_csharp_php_and_perl() {
        let cases = [
            ("Program.cs", Some("csharp")),
            ("Project.csproj", Some("csharp")),
            ("Solution.sln", Some("csharp")),
            ("main.php", Some("php")),
            ("view.PHTML", Some("php")),
            ("legacy.php5", Some("php")),
            ("modern.php7", Some("php")),
            ("source.PHPS", Some("php")),
            ("script.pl", Some("perl")),
            ("lib.pm", Some("perl")),
            ("basic.t", Some("perl")),
            ("app.psgi", Some("perl")),
            ("nope.txt", None),
        ];

        for (path, expected) in cases {
            assert_eq!(
                language_id_for_path(Path::new(path)),
                expected,
                "path={path}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn autodetect_server_includes_csharp_php_and_perl() -> anyhow::Result<()> {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir)?;

        let csharp_ls = dir.join("csharp-ls.cmd");
        fs::write(&csharp_ls, "@echo off\r\necho ok\r\n")?;

        let omnisharp = dir.join("OmniSharp.cmd");
        fs::write(&omnisharp, "@echo off\r\necho ok\r\n")?;

        let php = dir.join("intelephense.cmd");
        fs::write(&php, "@echo off\r\necho ok\r\n")?;

        let perl = dir.join("perlnavigator.cmd");
        fs::write(&perl, "@echo off\r\necho ok\r\n")?;

        let path_list = path_list_for(&dir);
        let csharp_cfg = autodetect_server_with("csharp", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            csharp_cfg,
            ServerConfig {
                command: csharp_ls.to_string_lossy().to_string(),
                args: vec!["--stdio".to_string()],
            }
        );

        fs::remove_file(&csharp_ls)?;
        let csharp_cfg = autodetect_server_with("csharp", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            csharp_cfg,
            ServerConfig {
                command: omnisharp.to_string_lossy().to_string(),
                args: vec!["--languageserver".to_string()],
            }
        );

        let php_cfg = autodetect_server_with("php", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            php_cfg,
            ServerConfig {
                command: php.to_string_lossy().to_string(),
                args: vec!["--stdio".to_string()],
            }
        );

        let perl_cfg = autodetect_server_with("perl", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            perl_cfg,
            ServerConfig {
                command: perl.to_string_lossy().to_string(),
                args: Vec::new(),
            }
        );

        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn autodetect_server_includes_csharp_php_and_perl() -> anyhow::Result<()> {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir)?;

        let csharp_ls = dir.join("csharp-ls");
        fs::write(&csharp_ls, "#!/bin/sh\nexit 0\n")?;
        make_executable(&csharp_ls)?;

        let omnisharp = dir.join("omnisharp");
        fs::write(&omnisharp, "#!/bin/sh\nexit 0\n")?;
        make_executable(&omnisharp)?;

        let php = dir.join("intelephense");
        fs::write(&php, "#!/bin/sh\nexit 0\n")?;
        make_executable(&php)?;

        let perl = dir.join("perlnavigator");
        fs::write(&perl, "#!/bin/sh\nexit 0\n")?;
        make_executable(&perl)?;

        let path_list = path_list_for(&dir);
        let csharp_cfg = autodetect_server_with("csharp", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            csharp_cfg,
            ServerConfig {
                command: csharp_ls.to_string_lossy().to_string(),
                args: vec!["--stdio".to_string()],
            }
        );

        fs::remove_file(&csharp_ls)?;
        let csharp_cfg = autodetect_server_with("csharp", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            csharp_cfg,
            ServerConfig {
                command: omnisharp.to_string_lossy().to_string(),
                args: vec!["--languageserver".to_string()],
            }
        );

        let php_cfg = autodetect_server_with("php", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            php_cfg,
            ServerConfig {
                command: php.to_string_lossy().to_string(),
                args: vec!["--stdio".to_string()],
            }
        );

        let perl_cfg = autodetect_server_with("perl", |candidates| {
            which_best_in(candidates, &path_list, &dir)
        })
        .unwrap();
        assert_eq!(
            perl_cfg,
            ServerConfig {
                command: perl.to_string_lossy().to_string(),
                args: Vec::new(),
            }
        );

        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
