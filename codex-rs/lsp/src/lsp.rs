use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use dunce::canonicalize as normalize_path;
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
use crate::watcher::ChangeKind;
use crate::watcher::FileChange;
use crate::watcher::start_watcher;

fn is_prewarm_language_id(language_id: &str) -> bool {
    matches!(
        language_id,
        "rust"
            | "go"
            | "python"
            | "typescript"
            | "typescriptreact"
            | "javascript"
            | "javascriptreact"
    )
}

fn detect_language_ids_for_root(root: &Path) -> std::collections::BTreeSet<String> {
    const MAX_ENTRIES: usize = 10_000;
    const MAX_DEPTH: usize = 6;

    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;

    while let Some((dir, depth)) = queue.pop() {
        if seen >= MAX_ENTRIES || depth > MAX_DEPTH {
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
                queue.push((path, depth.saturating_add(1)));
                continue;
            }

            if !ft.is_file() {
                continue;
            }

            if let Some(language_id) = language_id_for_path(&path)
                && is_prewarm_language_id(language_id)
            {
                found.insert(language_id.to_string());
                if found.len() >= 7 {
                    return found;
                }
            }
        }
    }

    found
}

fn normalize_root_path(root: &Path) -> PathBuf {
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

        let (tx, rx) = mpsc::unbounded_channel();
        let watcher = start_watcher(&root, tx).context("start filesystem watcher")?;

        state.workspaces.insert(
            root.clone(),
            WorkspaceState {
                root: root.clone(),
                _watcher: watcher,
                ignored,
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
            move || detect_language_ids_for_root(&root)
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
                    let mut state = self.inner.state.lock().await;
                    let Some(ws) = state.workspaces.get_mut(&root) else {
                        continue;
                    };
                    ws.servers
                        .insert(language_id.to_string(), Arc::clone(&server));
                    self.spawn_notification_loop(root.clone(), server);
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
        self.ensure_workspace(&root).await?;
        let path = path.map(|path| normalize_file_path(&root, path));
        let state = self.inner.state.lock().await;
        let ws = state
            .workspaces
            .get(&root)
            .context("workspace not initialized")?;
        Ok(ws.collect_diagnostics(path.as_deref(), max_results))
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

            if !ws.servers.contains_key(language_id) {
                let server = start_server(&ws.root, language_id, &config).await?;
                ws.servers
                    .insert(language_id.to_string(), Arc::clone(&server));
                self.spawn_notification_loop(root.clone(), Arc::clone(&server));
            }

            let server = ws
                .servers
                .get(language_id)
                .cloned()
                .context("server missing after initialization")?;

            let doc = ws
                .open_docs
                .entry(path.clone())
                .or_insert(OpenDocState { version: 0 });
            doc.version = doc.version.saturating_add(1);

            let version = doc.version;
            (server, version, version == 1)
        };

        if is_open {
            server.did_open(&path, language_id, version, &text).await?;
        } else {
            server.did_change(&path, version, &text).await?;
        }
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
    servers: HashMap<String, Arc<ServerState>>,
    open_docs: HashMap<PathBuf, OpenDocState>,
    diagnostics: BTreeMap<PathBuf, Vec<Diagnostic>>,
    diag_updates: tokio::sync::broadcast::Sender<DiagnosticsUpdate>,
}

impl WorkspaceState {
    fn is_ignored(&self, path: &Path) -> bool {
        let text = path.to_string_lossy();
        self.ignored.iter().any(|p| p.matches(&text))
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

    let mut cmd = Command::new(&server_config.command);
    cmd.args(&server_config.args)
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
    let pump = JsonRpcPump::new(Arc::clone(&client));
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

    initialize(&client, root).await?;

    Ok(Arc::new(ServerState {
        client,
        _child: Mutex::new(child),
        notifications: tx,
    }))
}

async fn initialize(client: &JsonRpcClient, root: &Path) -> anyhow::Result<()> {
    let root_uri = file_uri(root)?.to_string();
    let params = serde_json::json!({
        "processId": null,
        "rootUri": root_uri,
        "capabilities": {
            "textDocument": {
                "definition": { "dynamicRegistration": false },
                "references": { "dynamicRegistration": false },
                "documentSymbol": { "dynamicRegistration": false },
                // Some servers (notably `typescript-language-server`) only publish diagnostics if
                // the client advertises `textDocument.publishDiagnostics` support.
                "publishDiagnostics": { "relatedInformation": true },
                "synchronization": { "didSave": true }
            },
            "workspace": { "workspaceFolders": true }
        },
        "clientInfo": { "name": "codexel", "version": env!("CARGO_PKG_VERSION") }
    });
    let _ = client.request::<Value>("initialize", Some(params)).await?;
    client
        .notify::<Value>("initialized", Some(serde_json::json!({})))
        .await?;
    Ok(())
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
