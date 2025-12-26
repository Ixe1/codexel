use std::path::Path;

use which::which;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub command: String,
    pub args: Vec<String>,
}

pub(crate) fn autodetect_server(language_id: &str) -> Option<ServerConfig> {
    match language_id {
        "rust" => which("rust-analyzer").ok().map(|_| ServerConfig {
            command: "rust-analyzer".to_string(),
            args: Vec::new(),
        }),
        "go" => which("gopls").ok().map(|_| ServerConfig {
            command: "gopls".to_string(),
            args: Vec::new(),
        }),
        "python" => which("pyright-langserver").ok().map(|_| ServerConfig {
            command: "pyright-langserver".to_string(),
            args: vec!["--stdio".to_string()],
        }),
        "typescript" | "javascript" | "typescriptreact" | "javascriptreact" => {
            which("typescript-language-server")
                .ok()
                .map(|_| ServerConfig {
                    command: "typescript-language-server".to_string(),
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
