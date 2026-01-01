use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::features::Feature;
use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub struct LspHandler;

#[derive(Deserialize)]
struct LspDiagnosticsArgs {
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    max_results: Option<usize>,
}

#[derive(Deserialize)]
struct LspPositionArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    root: Option<String>,
}

#[derive(Deserialize)]
struct LspReferencesArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    include_declaration: bool,
    #[serde(default)]
    root: Option<String>,
}

#[derive(Deserialize)]
struct LspDocumentSymbolsArgs {
    file_path: String,
    #[serde(default)]
    root: Option<String>,
}

#[async_trait]
impl ToolHandler for LspHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        let ToolInvocation {
            payload,
            session,
            turn,
            tool_name,
            ..
        } = invocation;

        if !session.enabled(Feature::Lsp) {
            return Err(FunctionCallError::RespondToModel(
                "LSP tools are disabled. Enable `[features].lsp = true` in config.toml."
                    .to_string(),
            ));
        }

        let arguments = match payload {
            ToolPayload::Function { arguments } => arguments,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "lsp tool handler received unsupported payload".to_string(),
                ));
            }
        };

        let lsp = session.services.lsp_manager.clone();
        let max_default = turn.client.config().lsp.max_tool_diagnostics;
        let wait_ms = turn.client.config().lsp.tool_diagnostics_wait_ms;

        match tool_name.as_str() {
            "lsp_diagnostics" => {
                let args: LspDiagnosticsArgs = serde_json::from_str(&arguments).map_err(|err| {
                    FunctionCallError::RespondToModel(format!(
                        "failed to parse function arguments: {err:?}",
                    ))
                })?;

                let root = turn.resolve_path(args.root);
                let path = args
                    .path
                    .as_deref()
                    .map(|p| resolve_path_under_root(&root, p));
                let max_results = args.max_results.unwrap_or(max_default);

                let diags = lsp
                    .diagnostics_wait(
                        &root,
                        path.as_deref(),
                        max_results,
                        Duration::from_millis(wait_ms as u64),
                    )
                    .await
                    .map_err(|err| FunctionCallError::RespondToModel(format!("{err:#}")))?;

                let out = serde_json::json!({
                    "root": root,
                    "diagnostics": diags,
                });
                Ok(ToolOutput::Function {
                    content: serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string()),
                    content_items: None,
                    success: Some(true),
                })
            }
            "lsp_definition" => {
                let args: LspPositionArgs = serde_json::from_str(&arguments).map_err(|err| {
                    FunctionCallError::RespondToModel(format!(
                        "failed to parse function arguments: {err:?}",
                    ))
                })?;
                let root = turn.resolve_path(args.root);
                let path = resolve_path_under_root(&root, &args.file_path);
                let locations = lsp
                    .definition(
                        &root,
                        &path,
                        codex_lsp::Position {
                            line: args.line,
                            character: args.character,
                        },
                    )
                    .await
                    .map_err(|err| FunctionCallError::RespondToModel(format!("{err:#}")))?;

                let out = serde_json::json!({ "locations": locations });
                Ok(ToolOutput::Function {
                    content: serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string()),
                    content_items: None,
                    success: Some(true),
                    // It's useful to return `success=false` if we got no locations.
                })
            }
            "lsp_references" => {
                let args: LspReferencesArgs = serde_json::from_str(&arguments).map_err(|err| {
                    FunctionCallError::RespondToModel(format!(
                        "failed to parse function arguments: {err:?}",
                    ))
                })?;
                let root = turn.resolve_path(args.root);
                let path = resolve_path_under_root(&root, &args.file_path);
                let locations = lsp
                    .references(
                        &root,
                        &path,
                        codex_lsp::Position {
                            line: args.line,
                            character: args.character,
                        },
                        args.include_declaration,
                    )
                    .await
                    .map_err(|err| FunctionCallError::RespondToModel(format!("{err:#}")))?;

                let out = serde_json::json!({ "locations": locations });
                Ok(ToolOutput::Function {
                    content: serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string()),
                    content_items: None,
                    success: Some(true),
                })
            }
            "lsp_document_symbols" => {
                let args: LspDocumentSymbolsArgs =
                    serde_json::from_str(&arguments).map_err(|err| {
                        FunctionCallError::RespondToModel(format!(
                            "failed to parse function arguments: {err:?}",
                        ))
                    })?;
                let root = turn.resolve_path(args.root);
                let path = resolve_path_under_root(&root, &args.file_path);
                let symbols = lsp
                    .document_symbols(&root, &path)
                    .await
                    .map_err(|err| FunctionCallError::RespondToModel(format!("{err:#}")))?;

                let out = serde_json::json!({ "symbols": symbols });
                Ok(ToolOutput::Function {
                    content: serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string()),
                    content_items: None,
                    success: Some(true),
                })
            }
            _ => Err(FunctionCallError::RespondToModel(format!(
                "unknown lsp tool: {tool_name}",
            ))),
        }
    }
}

fn resolve_path_under_root(root: &Path, input: &str) -> PathBuf {
    let path = PathBuf::from(input);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}
