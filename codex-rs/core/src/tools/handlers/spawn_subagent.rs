use async_trait::async_trait;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentInvocation;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::user_input::UserInput;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::features::Feature;
use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub(crate) const SPAWN_SUBAGENT_TOOL_NAME: &str = "spawn_subagent";
pub(crate) const SPAWN_SUBAGENT_LABEL_PREFIX: &str = "spawn_subagent";

const SUBAGENT_DEVELOPER_PROMPT: &str = r#"You are a read-only subagent. You run in a restricted sandbox and must not modify files.

Hard rules:
- Do not ask the user questions.
- Do not propose or perform edits. Do not call apply_patch.
- Do not call spawn_subagent.
- You may explore the repo with read-only commands, but keep it minimal and avoid dumping large files.

Role:
You are a read-only subagent for Codex. Given the user's prompt, use the available tools to research and report back. Do what was asked; nothing more, nothing less.

Strengths:
- Searching for code, configurations, and patterns across large codebases.
- Investigating questions that require exploring multiple files.
- Summarizing findings with concrete evidence (file references + small snippets).

Guidelines:
- Start broad, then narrow down. Try multiple search strategies if the first attempt does not yield results.
- Prefer `rg` for searching; prefer targeted reads of specific files (avoid dumping large files).
- Be thorough, but keep evidence compact: include only the few most relevant snippets (small excerpts).
- Never create or modify files.
- Avoid emojis.
- In the final response, include relevant file paths and small code snippets. Prefer workspace-relative paths."#;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpawnSubagentArgs {
    description: String,
    prompt: String,
    label: Option<String>,
}

pub(crate) fn parse_spawn_subagent_invocation(
    arguments: &str,
) -> Result<SubAgentInvocation, String> {
    let args: SpawnSubagentArgs = serde_json::from_str(arguments)
        .map_err(|e| format!("failed to parse function arguments: {e:?}"))?;

    let description = normalize_description(&args.description);
    if description.is_empty() {
        return Err("description must be non-empty".to_string());
    }

    let prompt = args.prompt.trim();
    if prompt.is_empty() {
        return Err("prompt must be non-empty".to_string());
    }

    let label = sanitize_label(args.label.as_deref());

    Ok(SubAgentInvocation {
        description,
        label,
        prompt: prompt.to_string(),
    })
}

pub struct SpawnSubagentHandler;

#[async_trait]
impl ToolHandler for SpawnSubagentHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            call_id,
            payload,
            tool_name,
            ..
        } = invocation;

        let ToolPayload::Function { arguments } = payload else {
            return Err(FunctionCallError::RespondToModel(format!(
                "unsupported payload for {tool_name}"
            )));
        };

        let source = turn.client.get_session_source();
        if let SessionSource::SubAgent(_) = source {
            return Err(FunctionCallError::RespondToModel(
                "spawn_subagent is not supported inside subagents".to_string(),
            ));
        }

        let invocation = parse_spawn_subagent_invocation(&arguments)
            .map_err(FunctionCallError::RespondToModel)?;
        let label = invocation.label.clone();
        let subagent_label = format!("{SPAWN_SUBAGENT_LABEL_PREFIX}_{label}");

        let mut cfg = turn.client.config().as_ref().clone();
        cfg.developer_instructions = Some(build_subagent_developer_instructions(
            cfg.developer_instructions.as_deref().unwrap_or_default(),
        ));
        cfg.model = Some(turn.client.get_model());
        cfg.model_reasoning_effort = turn.client.get_reasoning_effort();
        cfg.model_reasoning_summary = turn.client.get_reasoning_summary();

        let mut features = cfg.features.clone();
        features.disable(Feature::ApplyPatchFreeform);
        cfg.features = features;
        cfg.approval_policy =
            crate::config::Constrained::allow_any(codex_protocol::protocol::AskForApproval::Never);
        cfg.sandbox_policy = crate::config::Constrained::allow_any(
            codex_protocol::protocol::SandboxPolicy::ReadOnly,
        );

        let input = vec![UserInput::Text {
            text: invocation.prompt.clone(),
        }];

        let response = crate::tools::subagent_runner::run_subagent_tool_call(
            Arc::clone(&session),
            Arc::clone(&turn),
            call_id,
            invocation,
            cfg,
            input,
            SubAgentSource::Other(subagent_label),
        )
        .await
        .map_err(FunctionCallError::RespondToModel)?;

        Ok(ToolOutput::Function {
            content: json!({
                "label": label,
                "response": response,
            })
            .to_string(),
            content_items: None,
            success: Some(true),
        })
    }
}

fn build_subagent_developer_instructions(existing: &str) -> String {
    let existing = existing.trim();
    if existing.is_empty() {
        return SUBAGENT_DEVELOPER_PROMPT.to_string();
    }
    format!("{SUBAGENT_DEVELOPER_PROMPT}\n\n{existing}")
}

fn sanitize_label(label: Option<&str>) -> String {
    let raw = label.unwrap_or_default().trim();
    let mut sanitized = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            sanitized.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        return "subagent".to_string();
    }
    const MAX_LEN: usize = 64;
    if sanitized.len() > MAX_LEN {
        sanitized.truncate(MAX_LEN);
    }
    sanitized
}

fn normalize_description(description: &str) -> String {
    description
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parse_requires_description() {
        let err = parse_spawn_subagent_invocation(r#"{"prompt":"hi"}"#).unwrap_err();
        assert!(
            err.contains("description"),
            "expected description error, got: {err}"
        );
    }

    #[test]
    fn parse_normalizes_description_whitespace() {
        let invocation = parse_spawn_subagent_invocation(
            r#"{"description":"  find \n  usage  docs  ","prompt":"  Hello  ","label":"My Label"}"#,
        )
        .expect("parse");

        assert_eq!(invocation.description, "find usage docs");
        assert_eq!(invocation.prompt, "Hello");
        assert_eq!(invocation.label, "my_label");
    }
}
