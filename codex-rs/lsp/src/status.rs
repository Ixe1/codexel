use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use crate::ServerConfig;
use crate::lsp::normalize_root_path;
use crate::servers::autodetect_server;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LspServerSource {
    Config,
    Autodetect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspLanguageStatus {
    pub language_id: String,
    pub configured: Option<ServerConfig>,
    pub autodetected: Option<ServerConfig>,
    pub effective: Option<(ServerConfig, LspServerSource)>,
    pub running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspStatus {
    pub enabled: bool,
    pub root: PathBuf,
    pub ignored_globs: Vec<String>,
    pub max_file_bytes: usize,
    pub workspace_initialized: bool,
    pub languages: Vec<LspLanguageStatus>,
}

pub(crate) fn status_language_ids(
    configured: impl Iterator<Item = String>,
    running: impl Iterator<Item = String>,
) -> Vec<String> {
    // Keep this list small and aligned with codex-lsp's autodetect map.
    const BUILTIN: [&str; 9] = [
        "rust",
        "go",
        "csharp",
        "python",
        "typescript",
        "javascript",
        "typescriptreact",
        "javascriptreact",
        "php",
        // "perl" is intentionally appended last; it may depend on a Perl runtime being installed.
    ];

    let mut out: BTreeSet<String> = BUILTIN.into_iter().map(str::to_string).collect();
    out.insert("perl".to_string());
    out.extend(configured);
    out.extend(running);
    out.into_iter().collect()
}

pub(crate) fn normalize_status_root(root: &Path) -> PathBuf {
    normalize_root_path(root)
}

pub fn render_lsp_status(status: &LspStatus) -> String {
    let enabled = status.enabled;
    let root = status.root.display();

    let mut lines = Vec::new();
    lines.push("## LSP status".to_string());
    lines.push(format!("- enabled: {enabled}"));
    lines.push(format!("- root: {root}"));
    lines.push(format!(
        "- workspace: {}",
        if status.workspace_initialized {
            "initialized"
        } else {
            "not initialized"
        }
    ));

    if !enabled {
        lines.push("- note: enable `[features].lsp = true` in config.toml".to_string());
        return lines.join("\n");
    }

    if !status.ignored_globs.is_empty() {
        let ignored = status
            .ignored_globs
            .iter()
            .map(|g| format!("`{g}`"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("- ignored: {ignored}"));
    }

    let max_file_bytes = status.max_file_bytes;
    lines.push(format!("- max_file_bytes: {max_file_bytes}"));

    lines.push("- servers:".to_string());
    for lang in &status.languages {
        let language_id = &lang.language_id;
        let running = if lang.running { "yes" } else { "no" };

        let configured = lang.configured.as_ref().map(server_cfg_display);
        let autodetected = lang.autodetected.as_ref().map(server_cfg_display);
        let effective = lang.effective.as_ref().map(|(cfg, source)| {
            let source = match source {
                LspServerSource::Config => "config",
                LspServerSource::Autodetect => "autodetect",
            };
            format!("{} ({source})", server_cfg_display(cfg))
        });

        let configured = configured.as_deref().unwrap_or("(none)");
        let autodetected = autodetected.as_deref().unwrap_or("(not found on PATH)");
        let effective = effective.as_deref().unwrap_or("(none)");

        lines.push(format!(
            "  - {language_id}: running={running}, effective={effective}, configured={configured}, detected={autodetected}",
        ));
    }

    lines.join("\n")
}

fn server_cfg_display(cfg: &ServerConfig) -> String {
    let command = cfg.command.trim();
    if cfg.args.is_empty() {
        return format!("`{command}`");
    }
    let args = cfg.args.join(" ");
    format!("`{command}` `{args}`")
}

pub(crate) fn effective_server_config(
    language_id: &str,
    configured: Option<&ServerConfig>,
) -> (
    Option<ServerConfig>,
    Option<ServerConfig>,
    Option<(ServerConfig, LspServerSource)>,
) {
    let autodetected = autodetect_server(language_id);
    let configured = configured.cloned();

    let effective = if let Some(cfg) = &configured {
        Some((cfg.clone(), LspServerSource::Config))
    } else {
        autodetected
            .clone()
            .map(|cfg| (cfg, LspServerSource::Autodetect))
    };

    (configured, autodetected, effective)
}
