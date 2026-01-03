use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use dunce::canonicalize as normalize_path;
use ignore::Match as GitignoreMatch;
use ignore::gitignore::Gitignore;
use ignore::gitignore::GitignoreBuilder;
use serde_json::Value;
use tokio::io::AsyncBufReadExt;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tracing::warn;
use wildmatch::WildMatchPattern;

use crate::jsonrpc::JsonRpcClient;
use crate::jsonrpc::JsonRpcPump;
use crate::jsonrpc::file_uri;
use crate::normalize::Diagnostic;
use crate::normalize::DiagnosticSeverity;
use crate::normalize::DiagnosticsUpdate;
use crate::normalize::DocumentSymbol;
use crate::normalize::Location;
use crate::normalize::Position;
use crate::normalize::Range;
use crate::servers::ServerConfig;
use crate::servers::autodetect_server;
use crate::servers::language_id_for_path;
use crate::status::LspStatus;
use crate::status::effective_server_config;
use crate::status::normalize_status_root;
use crate::status::status_language_ids;
use crate::watcher::ChangeKind;
use crate::watcher::FileChange;
use crate::watcher::start_watcher;

fn is_prewarm_language_id(language_id: &str) -> bool {
    matches!(
        language_id,
        "rust"
            | "go"
            | "csharp"
            | "python"
            | "typescript"
            | "typescriptreact"
            | "javascript"
            | "javascriptreact"
            | "php"
            | "perl"
    )
}

fn build_root_gitignore(root: &Path) -> Option<Gitignore> {
    let mut builder = GitignoreBuilder::new(root);
    let mut any_added = false;

    let gitignore_path = root.join(".gitignore");
    if gitignore_path.is_file() {
        if let Some(err) = builder.add(&gitignore_path) {
            warn!("failed to add {}: {err}", gitignore_path.display());
        } else {
            any_added = true;
        }
    }

    let git_exclude_path = root.join(".git").join("info").join("exclude");
    if git_exclude_path.is_file() {
        if let Some(err) = builder.add(&git_exclude_path) {
            warn!("failed to add {}: {err}", git_exclude_path.display());
        } else {
            any_added = true;
        }
    }

    if !any_added {
        return None;
    }

    match builder.build() {
        Ok(gitignore) => Some(gitignore),
        Err(err) => {
            warn!("failed to build gitignore matcher: {err}");
            None
        }
    }
}

fn is_gitignored(gitignore: &Gitignore, root: &Path, path: &Path, is_dir: bool) -> bool {
    if !path.starts_with(root) {
        return false;
    }
    matches!(
        gitignore.matched_path_or_any_parents(path, is_dir),
        GitignoreMatch::Ignore(_)
    )
}

fn detect_language_ids_for_root(
    root: &Path,
    ignored_globs: &[String],
) -> std::collections::BTreeSet<String> {
    const MAX_ENTRIES: usize = 10_000;
    const MAX_DEPTH: usize = 6;

    let ignored: Vec<WildMatchPattern<'*', '?'>> = ignored_globs
        .iter()
        .map(|s| WildMatchPattern::new_case_insensitive(s))
        .collect();
    let gitignore = build_root_gitignore(root);

    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;

    while let Some((dir, depth)) = queue.pop() {
        if seen >= MAX_ENTRIES || depth > MAX_DEPTH {
            continue;
        }

        if ignored.iter().any(|p| p.matches(&dir.to_string_lossy())) {
            continue;
        }
        if gitignore
            .as_ref()
            .is_some_and(|gitignore| is_gitignored(gitignore, root, &dir, true))
        {
            continue;
        }

        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in rd.flatten() {
            if seen >= MAX_ENTRIES {
                break;
            }
            seen += 1;

            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if ft.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if matches!(name, ".git" | "node_modules" | "target") {
                    continue;
                }
                if ignored.iter().any(|p| p.matches(&path.to_string_lossy())) {
                    continue;
                }
                if gitignore
                    .as_ref()
                    .is_some_and(|gitignore| is_gitignored(gitignore, root, &path, true))
                {
                    continue;
                }
                queue.push((path, depth.saturating_add(1)));
                continue;
            }

            if !ft.is_file() {
                continue;
            }

            if ignored.iter().any(|p| p.matches(&path.to_string_lossy())) {
                continue;
            }
            if gitignore
                .as_ref()
                .is_some_and(|gitignore| is_gitignored(gitignore, root, &path, false))
            {
                continue;
            }

            if let Some(language_id) = language_id_for_path(&path)
                && is_prewarm_language_id(language_id)
            {
                found.insert(language_id.to_string());
                if found.len() >= 9 {
                    return found;
                }
            }
        }
    }

    found
}

pub(crate) fn normalize_root_path(root: &Path) -> PathBuf {
    let root = if root.is_absolute() {
        root.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(root)
    } else {
        root.to_path_buf()
    };
    normalize_path(&root).unwrap_or(root)
}

fn normalize_file_path(root: &Path, path: &Path) -> PathBuf {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    normalize_path(&path).unwrap_or(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspManagerConfig {
    pub enabled: bool,
    pub servers: HashMap<String, ServerConfig>,
    pub ignored_globs: Vec<String>,
    pub max_file_bytes: usize,
}

impl Default for LspManagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            servers: HashMap::new(),
            ignored_globs: vec![
                "**/.git/**".to_string(),
                "**/node_modules/**".to_string(),
                "**/target/**".to_string(),
            ],
            max_file_bytes: 512 * 1024,
        }
    }
}

#[derive(Default)]
struct LspState {
    workspaces: HashMap<PathBuf, WorkspaceState>,
}

#[derive(Clone)]
pub struct LspManager {
    inner: Arc<Inner>,
}

struct Inner {
    config: RwLock<LspManagerConfig>,
    state: Mutex<LspState>,
}

impl LspManager {
    pub fn new(config: LspManagerConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config: RwLock::new(config),
                state: Mutex::new(LspState::default()),
            }),
        }
    }

    pub async fn set_config(&self, config: LspManagerConfig) {
        *self.inner.config.write().await = config;
    }

    pub async fn enabled(&self) -> bool {
        self.inner.config.read().await.enabled
    }

    pub async fn ensure_workspace(&self, root: &Path) -> anyhow::Result<()> {
        let root = normalize_root_path(root);
        let config = self.inner.config.read().await.clone();
        if !config.enabled {
            return Ok(());
        }

        let mut state = self.inner.state.lock().await;
        if state.workspaces.contains_key(&root) {
            return Ok(());
        }

        let ignored = config
            .ignored_globs
            .iter()
            .map(|s| WildMatchPattern::new_case_insensitive(s))
            .collect();
        let gitignore = build_root_gitignore(&root);

        let (tx, rx) = mpsc::unbounded_channel();
        let watcher = start_watcher(&root, tx).context("start filesystem watcher")?;

        state.workspaces.insert(
            root.clone(),
            WorkspaceState {
                root: root.clone(),
                _watcher: watcher,
                ignored,
                gitignore,
                servers: HashMap::new(),
                open_docs: HashMap::new(),
                diagnostics: BTreeMap::new(),
                diag_updates: tokio::sync::broadcast::channel(512).0,
            },
        );

        let manager = self.clone();
        let root = root.clone();
        tokio::spawn(async move {
            manager.run_change_loop(root, rx).await;
        });

        Ok(())
    }

    /// Best-effort background warmup for the LSP manager and configured language servers.
    ///
    /// Intended to run at session start so the first user-triggered LSP request doesn’t pay the
    /// full server spawn + initialize + indexing cost.
    pub async fn prewarm(&self, root: &Path) -> anyhow::Result<()> {
        let root = normalize_root_path(root);
        let config = self.inner.config.read().await.clone();
        if !config.enabled {
            return Ok(());
        }

        self.ensure_workspace(&root).await?;

        let detected = tokio::task::spawn_blocking({
            let root = root.clone();
            let ignored_globs = config.ignored_globs.clone();
            move || detect_language_ids_for_root(&root, &ignored_globs)
        })
        .await
        .unwrap_or_default();

        let mut language_ids: std::collections::BTreeSet<String> = config
            .servers
            .keys()
            .filter(|id| is_prewarm_language_id(id))
            .cloned()
            .collect();
        language_ids.extend(detected);

        for language_id in language_ids {
            {
                let state = self.inner.state.lock().await;
                let Some(ws) = state.workspaces.get(&root) else {
                    continue;
                };
                if ws.servers.contains_key(&language_id) {
                    continue;
                }
            }

            if !config.servers.contains_key(&language_id)
                && autodetect_server(&language_id).is_none()
            {
                continue;
            }

            match start_server(&root, &language_id, &config).await {
                Ok(server) => {
                    let mut inserted = false;
                    {
                        let mut state = self.inner.state.lock().await;
                        let Some(ws) = state.workspaces.get_mut(&root) else {
                            continue;
                        };
                        if !ws.servers.contains_key(&language_id) {
                            ws.servers
                                .insert(language_id.to_string(), Arc::clone(&server));
                            inserted = true;
                        }
                    }
                    if inserted {
                        self.spawn_notification_loop(root.clone(), server);
                    } else {
                        shutdown_unused_server(&language_id, server).await;
                    }
                }
                Err(err) => {
                    warn!("lsp prewarm failed for {language_id}: {err:#}");
                }
            }
        }

        Ok(())
    }

    async fn run_change_loop(&self, root: PathBuf, mut rx: mpsc::UnboundedReceiver<FileChange>) {
        let mut last_seen: HashMap<PathBuf, tokio::time::Instant> = HashMap::new();
        while let Some(change) = rx.recv().await {
            if change.kind == ChangeKind::Remove {
                continue;
            }
            if let Some(prev) = last_seen.get(&change.path)
                && prev.elapsed() < Duration::from_millis(75)
            {
                continue;
            }
            last_seen.insert(change.path.clone(), tokio::time::Instant::now());

            let language_id = match language_id_for_path(&change.path) {
                Some(id) => id,
                None => continue,
            };

            let bytes = match tokio::fs::read(&change.path).await {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if let Err(err) = self
                .open_or_update_with_text(&root, &change.path, language_id, bytes)
                .await
            {
                warn!("lsp sync failed: {err:#}");
            }
        }
    }

    pub async fn diagnostics(
        &self,
        root: &Path,
        path: Option<&Path>,
        max_results: usize,
    ) -> anyhow::Result<Vec<Diagnostic>> {
        let root = normalize_root_path(root);
        let config = self.inner.config.read().await.clone();
        if !config.enabled {
            return Ok(Vec::new());
        }
        self.ensure_workspace(&root).await?;
        let path = path.map(|path| normalize_file_path(&root, path));

        // Best-effort: make sure we have something to report for explicit queries.
        // Many servers don't proactively publish diagnostics unless a document is opened/updated.
        if let Some(path) = path.as_deref() {
            let _ = self.open_or_update(&root, path).await;
        } else {
            let _ = self.seed_diagnostics(&root).await;
        }

        let state = self.inner.state.lock().await;
        let ws = state
            .workspaces
            .get(&root)
            .context("workspace not initialized")?;
        Ok(ws.collect_diagnostics(path.as_deref(), max_results))
    }

    pub async fn diagnostics_wait(
        &self,
        root: &Path,
        path: Option<&Path>,
        max_results: usize,
        timeout: Duration,
    ) -> anyhow::Result<Vec<Diagnostic>> {
        let root = normalize_root_path(root);
        let config = self.inner.config.read().await.clone();
        if !config.enabled {
            return Ok(Vec::new());
        }

        self.ensure_workspace(&root).await?;
        let path = path.map(|path| normalize_file_path(&root, path));

        // Subscribe before triggering open/update so we don't miss a fast publishDiagnostics.
        let mut updates = self.subscribe_diagnostics(&root).await?;

        // Best-effort: make sure we have something to report for explicit queries.
        // Many servers don't proactively publish diagnostics unless a document is opened/updated.
        if let Some(path) = path.as_deref() {
            let _ = self.open_or_update(&root, path).await;

            // For pull-diagnostics servers, try again with a caller-provided timeout.
            // Some servers can take longer than the default per-request timeout while warming up.
            if timeout > Duration::from_secs(3)
                && let Ok(server) = self.server_for_path(&root, path).await
            {
                let _ = self
                    .refresh_pull_diagnostics_with_timeout(
                        root.clone(),
                        path.to_path_buf(),
                        server,
                        timeout,
                    )
                    .await;
            }
        } else {
            let _ = self.seed_diagnostics(&root).await;
        }

        if timeout.is_zero() {
            return self.diagnostics(&root, path.as_deref(), max_results).await;
        }

        let start = tokio::time::Instant::now();
        let deadline = start.checked_add(timeout).unwrap_or(start);
        let target_path = path.map(|p| normalize_path(&p).unwrap_or(p));

        loop {
            let diags = self
                .diagnostics(&root, target_path.as_deref(), max_results)
                .await?;
            if !diags.is_empty() {
                return Ok(diags);
            }

            let now = tokio::time::Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return Ok(diags);
            }

            let update = match tokio::time::timeout(remaining, updates.recv()).await {
                Ok(Ok(update)) => update,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => return Ok(diags),
                Err(_) => return Ok(diags),
            };

            if let Some(target_path) = &target_path {
                let update_path = PathBuf::from(&update.path);
                if update_path != *target_path {
                    continue;
                }
            }

            // We saw an update relevant to this request. Return whatever we have now (which may be
            // empty if the server explicitly cleared diagnostics).
            return self
                .diagnostics(&root, target_path.as_deref(), max_results)
                .await;
        }
    }

    async fn seed_diagnostics(&self, root: &Path) -> anyhow::Result<()> {
        let root = normalize_root_path(root);
        let config = self.inner.config.read().await.clone();
        if !config.enabled {
            return Ok(());
        }

        let ignored: Vec<WildMatchPattern<'*', '?'>> = config
            .ignored_globs
            .iter()
            .map(|s| WildMatchPattern::new_case_insensitive(s))
            .collect();
        let gitignore = build_root_gitignore(&root);

        // Only do work if we have no diagnostics yet.
        {
            let state = self.inner.state.lock().await;
            if let Some(ws) = state.workspaces.get(&root)
                && (!ws.diagnostics.is_empty() || !ws.open_docs.is_empty())
            {
                return Ok(());
            }
        }

        let mut queue = vec![(root.clone(), 0usize)];
        let mut seen = 0usize;
        while let Some((dir, depth)) = queue.pop() {
            if depth > 4 || seen > 2000 {
                break;
            }
            if ignored.iter().any(|p| p.matches(&dir.to_string_lossy())) {
                continue;
            }
            if gitignore
                .as_ref()
                .is_some_and(|gitignore| is_gitignored(gitignore, &root, &dir, true))
            {
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in rd.flatten() {
                if seen > 2000 {
                    break;
                }
                seen += 1;

                let path = entry.path();
                let file_type = match entry.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if file_type.is_dir() {
                    let name = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(str::to_ascii_lowercase)
                        .unwrap_or_default();
                    if matches!(
                        name.as_str(),
                        ".git" | "node_modules" | "target" | "bin" | "obj"
                    ) {
                        continue;
                    }
                    if ignored.iter().any(|p| p.matches(&path.to_string_lossy())) {
                        continue;
                    }
                    if gitignore
                        .as_ref()
                        .is_some_and(|gitignore| is_gitignored(gitignore, &root, &path, true))
                    {
                        continue;
                    }
                    queue.push((path, depth.saturating_add(1)));
                    continue;
                }

                if !file_type.is_file() {
                    continue;
                }

                if ignored.iter().any(|p| p.matches(&path.to_string_lossy())) {
                    continue;
                }
                if gitignore
                    .as_ref()
                    .is_some_and(|gitignore| is_gitignored(gitignore, &root, &path, false))
                {
                    continue;
                }

                if let Some(language_id) = language_id_for_path(&path)
                    && (is_prewarm_language_id(language_id)
                        || config.servers.contains_key(language_id))
                {
                    self.open_or_update(&root, &path).await?;
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    pub async fn status(&self, root: &Path) -> anyhow::Result<LspStatus> {
        let root = normalize_status_root(root);
        let config = self.inner.config.read().await.clone();

        if config.enabled {
            self.ensure_workspace(&root).await?;
        }

        let (workspace_initialized, running_servers, pull_diagnostics) = {
            let state = self.inner.state.lock().await;
            match state.workspaces.get(&root) {
                Some(ws) => (
                    true,
                    ws.servers.keys().cloned().collect::<Vec<String>>(),
                    ws.servers
                        .iter()
                        .map(|(language_id, server)| {
                            (language_id.clone(), server.supports_pull_diagnostics)
                        })
                        .collect::<HashMap<String, bool>>(),
                ),
                None => (false, Vec::new(), HashMap::new()),
            }
        };

        let language_ids = status_language_ids(
            config.servers.keys().cloned(),
            running_servers.clone().into_iter(),
        );

        let mut languages = Vec::new();
        for language_id in language_ids {
            let running = running_servers.contains(&language_id);
            let supports_pull_diagnostics = if running {
                pull_diagnostics.get(&language_id).copied()
            } else {
                None
            };
            let configured = config.servers.get(&language_id);
            let (configured, autodetected, effective) =
                effective_server_config(&language_id, configured);

            languages.push(crate::status::LspLanguageStatus {
                language_id,
                configured,
                autodetected,
                effective,
                running,
                supports_pull_diagnostics,
            });
        }

        Ok(LspStatus {
            enabled: config.enabled,
            root,
            ignored_globs: config.ignored_globs,
            max_file_bytes: config.max_file_bytes,
            workspace_initialized,
            languages,
        })
    }

    pub async fn subscribe_diagnostics(
        &self,
        root: &Path,
    ) -> anyhow::Result<tokio::sync::broadcast::Receiver<DiagnosticsUpdate>> {
        let root = normalize_root_path(root);
        self.ensure_workspace(&root).await?;
        let state = self.inner.state.lock().await;
        let ws = state
            .workspaces
            .get(&root)
            .context("workspace not initialized")?;
        Ok(ws.diag_updates.subscribe())
    }

    pub async fn definition(
        &self,
        root: &Path,
        path: &Path,
        position: Position,
    ) -> anyhow::Result<Vec<Location>> {
        let root = normalize_root_path(root);
        let path = normalize_file_path(&root, path);
        self.ensure_workspace(&root).await?;
        self.open_or_update(&root, &path).await?;
        let server = self.server_for_path(&root, &path).await?;
        server.definition(&path, position).await
    }

    pub async fn references(
        &self,
        root: &Path,
        path: &Path,
        position: Position,
        include_declaration: bool,
    ) -> anyhow::Result<Vec<Location>> {
        let root = normalize_root_path(root);
        let path = normalize_file_path(&root, path);
        self.ensure_workspace(&root).await?;
        self.open_or_update(&root, &path).await?;
        let server = self.server_for_path(&root, &path).await?;
        server
            .references(&path, position, include_declaration)
            .await
    }

    pub async fn document_symbols(
        &self,
        root: &Path,
        path: &Path,
    ) -> anyhow::Result<Vec<DocumentSymbol>> {
        let root = normalize_root_path(root);
        let path = normalize_file_path(&root, path);
        self.ensure_workspace(&root).await?;
        self.open_or_update(&root, &path).await?;
        let server = self.server_for_path(&root, &path).await?;
        server.document_symbols(&path).await
    }

    async fn server_for_path(&self, root: &Path, path: &Path) -> anyhow::Result<Arc<ServerState>> {
        let language_id = language_id_for_path(path).context("unknown language id for file")?;
        let state = self.inner.state.lock().await;
        let ws = state
            .workspaces
            .get(root)
            .context("workspace not initialized")?;
        ws.servers
            .get(language_id)
            .cloned()
            .with_context(|| format!("language server not started for '{language_id}'"))
    }

    async fn open_or_update(&self, root: &Path, path: &Path) -> anyhow::Result<()> {
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("read {}", path.display()))?;
        let language_id = language_id_for_path(path).context("unknown language id for file")?;
        self.open_or_update_with_text(root, path, language_id, bytes)
            .await
    }

    async fn open_or_update_with_text(
        &self,
        root: &Path,
        path: &Path,
        language_id: &str,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let root = normalize_root_path(root);
        let path = normalize_file_path(&root, path);
        let config = self.inner.config.read().await.clone();
        if !config.enabled {
            return Ok(());
        }

        let text = String::from_utf8_lossy(&bytes).to_string();
        if config.max_file_bytes > 0 && bytes.len() > config.max_file_bytes {
            return Ok(());
        }

        let (server, version, is_open) = {
            let mut state = self.inner.state.lock().await;
            let ws = state
                .workspaces
                .get_mut(&root)
                .context("workspace not initialized")?;

            if ws.is_ignored(&path) {
                return Ok(());
            }

            let server = ws.servers.get(language_id).cloned();

            let doc = ws
                .open_docs
                .entry(path.clone())
                .or_insert(OpenDocState { version: 0 });
            doc.version = doc.version.saturating_add(1);

            let version = doc.version;
            (server, version, version == 1)
        };

        let server = match server {
            Some(server) => server,
            None => {
                let spawned = start_server(&root, language_id, &config).await?;
                let mut inserted = false;
                let effective = {
                    let mut state = self.inner.state.lock().await;
                    let ws = state
                        .workspaces
                        .get_mut(&root)
                        .context("workspace not initialized")?;
                    if ws.is_ignored(&path) {
                        return Ok(());
                    }
                    if let Some(existing) = ws.servers.get(language_id).cloned() {
                        existing
                    } else {
                        ws.servers
                            .insert(language_id.to_string(), Arc::clone(&spawned));
                        inserted = true;
                        Arc::clone(&spawned)
                    }
                };
                if inserted {
                    self.spawn_notification_loop(root.clone(), Arc::clone(&effective));
                } else {
                    shutdown_unused_server(language_id, spawned).await;
                }
                effective
            }
        };

        if is_open {
            server.did_open(&path, language_id, version, &text).await?;
        } else {
            server.did_change(&path, version, &text).await?;
        }

        if let Err(err) = self
            .refresh_pull_diagnostics(root.clone(), path.clone(), Arc::clone(&server))
            .await
        {
            warn!("lsp pull diagnostics failed: {err:#}");
        }
        Ok(())
    }

    async fn refresh_pull_diagnostics(
        &self,
        root: PathBuf,
        path: PathBuf,
        server: Arc<ServerState>,
    ) -> anyhow::Result<()> {
        self.refresh_pull_diagnostics_with_timeout(root, path, server, Duration::from_secs(3))
            .await
    }

    async fn refresh_pull_diagnostics_with_timeout(
        &self,
        root: PathBuf,
        path: PathBuf,
        server: Arc<ServerState>,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let Some(diags) = server.pull_diagnostics_with_timeout(&path, timeout).await? else {
            return Ok(());
        };

        let path = normalize_path(&path).unwrap_or(path);
        let update = DiagnosticsUpdate {
            path: path.to_string_lossy().into_owned(),
            diagnostics: diags.clone(),
        };
        let update_sender = {
            let mut state = self.inner.state.lock().await;
            let Some(ws) = state.workspaces.get_mut(&root) else {
                return Ok(());
            };
            ws.diagnostics.insert(path, diags);
            ws.diag_updates.clone()
        };
        let _ = update_sender.send(update);
        Ok(())
    }

    fn spawn_notification_loop(&self, root: PathBuf, server: Arc<ServerState>) {
        let manager = self.clone();
        let mut rx = server.notifications.subscribe();
        tokio::spawn(async move {
            while let Ok((method, params)) = rx.recv().await {
                if method != "textDocument/publishDiagnostics" {
                    continue;
                }
                let Some(params) = params else { continue };
                let Some((path, diags)) = parse_publish_diagnostics(&params) else {
                    continue;
                };
                let path = normalize_path(&path).unwrap_or(path);
                let update = DiagnosticsUpdate {
                    path: path.to_string_lossy().into_owned(),
                    diagnostics: diags.clone(),
                };
                let update_sender = {
                    let mut state = manager.inner.state.lock().await;
                    let Some(ws) = state.workspaces.get_mut(&root) else {
                        continue;
                    };
                    ws.diagnostics.insert(path, diags);
                    ws.diag_updates.clone()
                };
                let _ = update_sender.send(update);
            }
        });
    }
}

struct WorkspaceState {
    root: PathBuf,
    _watcher: notify::RecommendedWatcher,
    ignored: Vec<WildMatchPattern<'*', '?'>>,
    gitignore: Option<Gitignore>,
    servers: HashMap<String, Arc<ServerState>>,
    open_docs: HashMap<PathBuf, OpenDocState>,
    diagnostics: BTreeMap<PathBuf, Vec<Diagnostic>>,
    diag_updates: tokio::sync::broadcast::Sender<DiagnosticsUpdate>,
}

impl WorkspaceState {
    fn is_ignored(&self, path: &Path) -> bool {
        let text = path.to_string_lossy();
        if self.ignored.iter().any(|p| p.matches(&text)) {
            return true;
        }
        let Some(gitignore) = &self.gitignore else {
            return false;
        };
        is_gitignored(gitignore, &self.root, path, false)
    }

    fn collect_diagnostics(&self, path: Option<&Path>, max_results: usize) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        if let Some(path) = path {
            if let Some(diags) = self.diagnostics.get(path) {
                out.extend(diags.iter().cloned());
            }
        } else {
            for diags in self.diagnostics.values() {
                out.extend(diags.iter().cloned());
            }
        }
        out.sort_by(|a, b| {
            (
                severity_rank(a.severity),
                &a.path,
                a.range.start.line,
                a.range.start.character,
            )
                .cmp(&(
                    severity_rank(b.severity),
                    &b.path,
                    b.range.start.line,
                    b.range.start.character,
                ))
        });
        if max_results > 0 && out.len() > max_results {
            out.truncate(max_results);
        }
        out
    }
}

fn severity_rank(sev: Option<DiagnosticSeverity>) -> u8 {
    match sev {
        Some(DiagnosticSeverity::Error) => 0,
        Some(DiagnosticSeverity::Warning) => 1,
        Some(DiagnosticSeverity::Information) => 2,
        Some(DiagnosticSeverity::Hint) => 3,
        None => 4,
    }
}

#[derive(Debug, Clone)]
struct OpenDocState {
    version: i32,
}

struct ServerState {
    client: Arc<JsonRpcClient>,
    _child: Mutex<Child>,
    notifications: tokio::sync::broadcast::Sender<(String, Option<Value>)>,
    supports_pull_diagnostics: bool,
}

impl Drop for ServerState {
    fn drop(&mut self) {
        if let Ok(mut child) = self._child.try_lock() {
            let _ = child.start_kill();
        }
    }
}

impl ServerState {
    async fn did_open(
        &self,
        path: &Path,
        language_id: &str,
        version: i32,
        text: &str,
    ) -> anyhow::Result<()> {
        let uri = file_uri(path)?.to_string();
        tracing::debug!(
            "lsp didOpen: uri={} language_id={} version={} bytes={}",
            uri,
            language_id,
            version,
            text.len()
        );
        let params = serde_json::json!({
            "textDocument": {
                "uri": uri,
                "languageId": language_id,
                "version": version,
                "text": text,
            }
        });
        self.client
            .notify("textDocument/didOpen", Some(params))
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }

    async fn did_change(&self, path: &Path, version: i32, text: &str) -> anyhow::Result<()> {
        let uri = file_uri(path)?.to_string();
        let params = serde_json::json!({
            "textDocument": { "uri": uri, "version": version },
            "contentChanges": [{ "text": text }]
        });
        self.client
            .notify("textDocument/didChange", Some(params))
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }

    async fn definition(&self, path: &Path, position: Position) -> anyhow::Result<Vec<Location>> {
        let uri = file_uri(path)?.to_string();
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": { "line": position.line.saturating_sub(1), "character": position.character.saturating_sub(1) }
        });
        let value = self
            .client
            .request("textDocument/definition", Some(params))
            .await
            .map_err(anyhow::Error::from)?;
        Ok(parse_locations(value))
    }

    async fn references(
        &self,
        path: &Path,
        position: Position,
        include_declaration: bool,
    ) -> anyhow::Result<Vec<Location>> {
        let uri = file_uri(path)?.to_string();
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": { "line": position.line.saturating_sub(1), "character": position.character.saturating_sub(1) },
            "context": { "includeDeclaration": include_declaration }
        });
        let value = self
            .client
            .request("textDocument/references", Some(params))
            .await
            .map_err(anyhow::Error::from)?;
        Ok(parse_locations(value))
    }

    async fn document_symbols(&self, path: &Path) -> anyhow::Result<Vec<DocumentSymbol>> {
        let uri = file_uri(path)?.to_string();
        let params = serde_json::json!({ "textDocument": { "uri": uri }});
        let value = self
            .client
            .request("textDocument/documentSymbol", Some(params))
            .await
            .map_err(anyhow::Error::from)?;
        Ok(parse_document_symbols(value))
    }

    async fn pull_diagnostics_with_timeout(
        &self,
        path: &Path,
        timeout: Duration,
    ) -> anyhow::Result<Option<Vec<Diagnostic>>> {
        if !self.supports_pull_diagnostics {
            return Ok(None);
        }

        let uri = file_uri(path)?.to_string();
        tracing::debug!("lsp pull diagnostics: uri={uri}");
        let params = serde_json::json!({ "textDocument": { "uri": uri }});
        let value = tokio::time::timeout(
            timeout,
            self.client
                .request("textDocument/diagnostic", Some(params.clone())),
        )
        .await
        .with_context(|| {
            format!(
                "LSP textDocument/diagnostic timed out after {}ms",
                timeout.as_millis()
            )
        })?
        .map_err(anyhow::Error::from)?;

        if value.get("kind").and_then(Value::as_str) == Some("unchanged") {
            return Ok(None);
        }

        let diags = parse_text_document_diagnostic(path, &value).unwrap_or_default();
        tracing::debug!("lsp pull diagnostics: count={}", diags.len());
        Ok(Some(diags))
    }
}

async fn start_server(
    root: &Path,
    language_id: &str,
    config: &LspManagerConfig,
) -> anyhow::Result<Arc<ServerState>> {
    let server_config = config
        .servers
        .get(language_id)
        .cloned()
        .or_else(|| autodetect_server(language_id))
        .with_context(|| format!("no language server configured for '{language_id}'"))?;

    let mut args = server_config.args.clone();

    // `csharp-ls` supports `--solution <path>` and needs a workspace to provide project-level
    // diagnostics. If we can unambiguously pick a solution file at the workspace root, pass it.
    if language_id == "csharp" && args.is_empty() {
        let looks_like_csharp_ls = std::path::Path::new(&server_config.command)
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase().starts_with("csharp-ls"))
            .unwrap_or(false);

        if looks_like_csharp_ls {
            let mut slns = Vec::new();
            if let Ok(rd) = std::fs::read_dir(root) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let ext = path
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(str::to_ascii_lowercase);
                    if matches!(ext.as_deref(), Some("sln" | "slnx"))
                        && let Some(name) = path.file_name().and_then(|s| s.to_str())
                    {
                        slns.push(name.to_string());
                    }
                }
            }
            slns.sort();
            slns.dedup();
            if slns.len() == 1 {
                args.push("--solution".to_string());
                args.push(slns[0].clone());
            }
        }
    }

    let mut cmd = Command::new(&server_config.command);
    cmd.args(&args)
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().with_context(|| {
        format!(
            "spawn language server {} {}",
            server_config.command,
            server_config.args.join(" ")
        )
    })?;

    let stdin = child
        .stdin
        .take()
        .context("missing language server stdin")?;
    let stdout = child
        .stdout
        .take()
        .context("missing language server stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("missing language server stderr")?;

    let client = Arc::new(JsonRpcClient::new(Box::new(stdin)));

    let (tx, _) = tokio::sync::broadcast::channel(512);
    let pump_tx = tx.clone();
    let root_uri = file_uri(root)?.to_string();
    let pump = JsonRpcPump::new(Arc::clone(&client), root_uri);
    tokio::spawn(async move {
        let (notif_tx, mut notif_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some((method, params)) = notif_rx.recv().await {
                let _ = pump_tx.send((method, params));
            }
        });
        if let Err(err) = pump.run(stdout, notif_tx).await {
            warn!("jsonrpc pump exited: {err}");
        }
    });

    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => tracing::debug!("lsp stderr: {}", line.trim_end()),
                Err(_) => break,
            }
        }
    });

    let supports_pull_diagnostics = initialize(&client, root).await?;

    Ok(Arc::new(ServerState {
        client,
        _child: Mutex::new(child),
        notifications: tx,
        supports_pull_diagnostics,
    }))
}

async fn shutdown_unused_server(language_id: &str, server: Arc<ServerState>) {
    let mut child = server._child.lock().await;
    if let Err(err) = child.kill().await {
        tracing::debug!("failed to kill unused lsp server {language_id}: {err}");
    }
}

async fn initialize(client: &JsonRpcClient, root: &Path) -> anyhow::Result<bool> {
    let root_uri = file_uri(root)?.to_string();
    let root_uri_folder = root_uri.clone();
    let process_id = std::process::id();
    let params = serde_json::json!({
        "processId": process_id,
        "rootUri": root_uri,
        "workspaceFolders": [{ "uri": root_uri_folder, "name": "root" }],
        "capabilities": {
            "textDocument": {
                "definition": { "dynamicRegistration": false },
                "references": { "dynamicRegistration": false },
                "documentSymbol": { "dynamicRegistration": false },
                // Some servers (notably `typescript-language-server`) only publish diagnostics if
                // the client advertises `textDocument.publishDiagnostics` support.
                "publishDiagnostics": { "relatedInformation": true },
                // Some servers (notably `csharp-ls`) support pull diagnostics via
                // `textDocument/diagnostic` and require the client to advertise this capability.
                "diagnostic": { "dynamicRegistration": false, "relatedDocumentSupport": true },
                "synchronization": { "didSave": true }
            },
            "workspace": { "workspaceFolders": true }
        },
        "clientInfo": { "name": "codexel", "version": env!("CARGO_PKG_VERSION") }
    });
    let init_result = tokio::time::timeout(
        Duration::from_secs(30),
        client.request::<Value>("initialize", Some(params)),
    )
    .await
    .context("LSP initialize timed out")??;
    client
        .notify::<Value>("initialized", Some(serde_json::json!({})))
        .await?;

    let supports_pull_diagnostics = init_result
        .get("capabilities")
        .and_then(|caps| caps.get("diagnosticProvider"))
        .is_some();

    Ok(supports_pull_diagnostics)
}

fn parse_publish_diagnostics(params: &Value) -> Option<(PathBuf, Vec<Diagnostic>)> {
    let uri = params.get("uri")?.as_str()?;
    let path = url::Url::parse(uri)
        .ok()?
        .to_file_path()
        .ok()
        .map(|path| normalize_path(&path).unwrap_or(path))?;
    let raw = params.get("diagnostics")?.as_array()?;
    let mut out = Vec::with_capacity(raw.len());
    for d in raw {
        if let Some(diag) = parse_diagnostic(&path, d) {
            out.push(diag);
        }
    }
    Some((path, out))
}

fn parse_text_document_diagnostic(path: &Path, value: &Value) -> Option<Vec<Diagnostic>> {
    let Value::Object(map) = value else {
        return None;
    };
    if map.get("kind").and_then(Value::as_str) == Some("unchanged") {
        return None;
    }
    let items = map.get("items")?.as_array()?;

    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if let Some(diag) = parse_diagnostic(path, item) {
            out.push(diag);
        }
    }
    Some(out)
}

fn parse_diagnostic(path: &Path, v: &Value) -> Option<Diagnostic> {
    let message = v.get("message")?.as_str()?.to_string();
    let range = parse_range(v.get("range")?)?;
    let severity = v
        .get("severity")
        .and_then(Value::as_u64)
        .and_then(|n| match n {
            1 => Some(DiagnosticSeverity::Error),
            2 => Some(DiagnosticSeverity::Warning),
            3 => Some(DiagnosticSeverity::Information),
            4 => Some(DiagnosticSeverity::Hint),
            _ => None,
        });
    let source = v
        .get("source")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let code = match v.get("code") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };
    Some(Diagnostic {
        path: path.to_string_lossy().into_owned(),
        range,
        severity,
        code,
        source,
        message,
    })
}

fn parse_range(v: &Value) -> Option<Range> {
    let start = parse_position(v.get("start")?)?;
    let end = parse_position(v.get("end")?)?;
    Some(Range { start, end })
}

fn parse_position(v: &Value) -> Option<Position> {
    let line = v.get("line")?.as_u64()? as u32;
    let character = v.get("character")?.as_u64()? as u32;
    Some(Position {
        line: line.saturating_add(1),
        character: character.saturating_add(1),
    })
}

fn parse_locations(value: Value) -> Vec<Location> {
    match value {
        Value::Null => Vec::new(),
        Value::Array(arr) => arr.into_iter().flat_map(parse_location_like).collect(),
        other => parse_location_like(other),
    }
}

fn parse_location_like(value: Value) -> Vec<Location> {
    // Location
    if let Some(uri) = value.get("uri").and_then(Value::as_str)
        && let Some(range_value) = value.get("range")
        && let Some(range) = parse_range(range_value)
        && let Some(path) = url::Url::parse(uri)
            .ok()
            .and_then(|u| u.to_file_path().ok())
    {
        let path = normalize_path(&path).unwrap_or(path);
        return vec![Location {
            path: path.to_string_lossy().into_owned(),
            range,
        }];
    }

    // LocationLink
    if let Some(target_uri) = value.get("targetUri").and_then(Value::as_str)
        && let Some(range_value) = value.get("targetRange")
        && let Some(range) = parse_range(range_value)
        && let Some(path) = url::Url::parse(target_uri)
            .ok()
            .and_then(|u| u.to_file_path().ok())
    {
        let path = normalize_path(&path).unwrap_or(path);
        return vec![Location {
            path: path.to_string_lossy().into_owned(),
            range,
        }];
    }

    Vec::new()
}

fn parse_document_symbols(value: Value) -> Vec<DocumentSymbol> {
    match value {
        Value::Array(arr) => arr.into_iter().filter_map(parse_document_symbol).collect(),
        _ => Vec::new(),
    }
}

fn parse_document_symbol(value: Value) -> Option<DocumentSymbol> {
    let name = value.get("name")?.as_str()?.to_string();
    let kind = value.get("kind")?.as_u64()? as u32;
    let range = parse_range(value.get("range")?)?;
    let selection_range = parse_range(value.get("selectionRange")?)?;
    let children = value
        .get("children")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .cloned()
                .filter_map(parse_document_symbol)
                .collect()
        })
        .unwrap_or_default();
    Some(DocumentSymbol {
        name,
        kind,
        range,
        selection_range,
        children,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use pretty_assertions::assert_eq;

    use super::detect_language_ids_for_root;

    #[test]
    fn prewarm_detection_respects_gitignore() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".gitignore"), "tmp/lsp-smoke/\n").unwrap();
        fs::create_dir_all(dir.path().join("tmp/lsp-smoke")).unwrap();
        fs::write(
            dir.path().join("tmp/lsp-smoke/php_lsp_smoke.php"),
            "<?php echo 1;",
        )
        .unwrap();

        let ids = detect_language_ids_for_root(dir.path(), &[]);
        assert_eq!(ids.contains("php"), false);

        fs::write(dir.path().join("index.php"), "<?php echo 2;").unwrap();
        let ids = detect_language_ids_for_root(dir.path(), &[]);
        assert_eq!(ids.contains("php"), true);
    }
}
