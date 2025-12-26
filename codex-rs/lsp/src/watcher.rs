use std::path::Path;
use std::path::PathBuf;

use notify::EventKind;
use notify::RecommendedWatcher;
use notify::RecursiveMode;
use notify::Watcher;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    CreateOrModify,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: PathBuf,
    pub kind: ChangeKind,
}

pub(crate) fn start_watcher(
    root: &Path,
    tx: tokio::sync::mpsc::UnboundedSender<FileChange>,
) -> notify::Result<RecommendedWatcher> {
    let root = root.to_path_buf();
    let root_for_filter = root.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            let kind = match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => ChangeKind::CreateOrModify,
                EventKind::Remove(_) => ChangeKind::Remove,
                _ => return,
            };
            for path in event.paths {
                if path.starts_with(&root_for_filter) {
                    let _ = tx.send(FileChange { path, kind });
                }
            }
        }
    })?;

    watcher.watch(root.as_path(), RecursiveMode::Recursive)?;
    Ok(watcher)
}
