use async_trait::async_trait;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::user_input::UserInput;
use serde_json::json;
use std::sync::Arc;

use crate::features::Feature;
use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::parse_spawn_subagent_invocation;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub(crate) const SPAWN_MINI_SUBAGENT_TOOL_NAME: &str = "spawn_mini_subagent";
pub(crate) const SPAWN_MINI_SUBAGENT_LABEL_PREFIX: &str = "spawn_mini_subagent";

pub(crate) const DEFAULT_MINI_SUBAGENT_MODEL_SLUG: &str = "gpt-5.1-codex-mini";

const MINI_SUBAGENT_DEVELOPER_PROMPT: &str = r#"You are a read-only subagent running on a smaller/cheaper model.

Hard rules:
- Do not ask the user questions.
- Do not propose or perform edits. Do not call apply_patch.
- Do not call spawn_subagent or spawn_mini_subagent.
- You may explore the repo with read-only commands, but keep it minimal and avoid dumping large files.

Role:
You are a read-only subagent for Codex. Given the user's prompt, use the available tools to research and report back. Do what was asked; nothing more, nothing less.

Guidelines:
- Prefer fast, low-risk work: quick repo search, entry-point mapping, and pattern matching.
- If the correct answer requires deep reasoning or large-scale redesign judgment, say so plainly and suggest using a stronger model.
- Keep your report concise and concrete: include relevant file paths and small snippets. Prefer workspace-relative paths."#;

pub struct SpawnMiniSubagentHandler;

#[async_trait]
impl ToolHandler for SpawnMiniSubagentHandler {
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
                "spawn_mini_subagent is not supported inside subagents".to_string(),
            ));
        }

        let mut invocation = parse_spawn_subagent_invocation(&arguments)
            .map_err(FunctionCallError::RespondToModel)?;

        let label = invocation.label.clone();
        let subagent_label = format!("{SPAWN_MINI_SUBAGENT_LABEL_PREFIX}_{label}");

        let model = turn
            .mini_subagent_model
            .clone()
            .unwrap_or_else(|| DEFAULT_MINI_SUBAGENT_MODEL_SLUG.to_string());
        invocation.model = Some(model.clone());

        let mut cfg = turn.client.config().as_ref().clone();
        cfg.developer_instructions = Some(build_mini_subagent_developer_instructions(
            cfg.developer_instructions.as_deref().unwrap_or_default(),
        ));
        cfg.model = Some(model);
        cfg.model_reasoning_effort = turn
            .mini_subagent_reasoning_effort
            .or(Some(codex_protocol::openai_models::ReasoningEffort::Medium));
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

fn build_mini_subagent_developer_instructions(existing: &str) -> String {
    let existing = existing.trim();
    if existing.is_empty() {
        return MINI_SUBAGENT_DEVELOPER_PROMPT.to_string();
    }
    format!("{MINI_SUBAGENT_DEVELOPER_PROMPT}\n\n{existing}")
}
