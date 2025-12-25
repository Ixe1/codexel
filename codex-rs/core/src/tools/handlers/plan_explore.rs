use async_trait::async_trait;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentInvocation;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::user_input::UserInput;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::DEFAULT_MINI_SUBAGENT_MODEL_SLUG;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub(crate) const PLAN_EXPLORE_TOOL_NAME: &str = "plan_explore";

pub struct PlanExploreHandler;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanExploreArgs {
    goal: String,
    explorers: Option<Vec<ExplorerArgs>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplorerArgs {
    focus: String,
    description: Option<String>,
    prompt: Option<String>,
}

const DEFAULT_TOTAL_EXPLORERS: usize = 3;

const PLAN_EXPLORE_PROMPT: &str = r#"You are a read-only exploration subagent helping another agent write an implementation plan.

Hard rules:
- Do not ask the user questions.
- Do not propose or perform edits. Do not call apply_patch.
- Do not call propose_plan_variants.
- Do not call spawn_subagent.
- You may explore the repo with read-only commands, but keep it minimal (2-6 targeted commands) and avoid dumping large files.

Output requirements:
- Return a concise plain-text report (aim for ~10-25 lines).
- Include a short "Key paths" list of the most relevant files/modules.
- Include a short "Entry points / call chain" if applicable.
- Include any gotchas (tests, platform constraints, config knobs) that affect the plan."#;

fn explorer_focus(idx: usize) -> &'static str {
    match idx {
        1 => "Repo map + likely touchpoints (where changes would land).",
        2 => "Entry points + control flow (where the behavior is wired).",
        3 => "Validation + risks (tests/commands, edge cases, rollback notes).",
        _ => "General exploration.",
    }
}

async fn run_one_explorer(
    call_id: String,
    invocation: SubAgentInvocation,
    base_config: Config,
    idx: usize,
    focus: String,
    parent_session: Arc<crate::codex::Session>,
    parent_ctx: Arc<crate::codex::TurnContext>,
) -> String {
    let mut cfg = base_config;
    let mut invocation = invocation;

    // Keep this prompt focused and small; avoid inheriting large caller developer instructions.
    cfg.developer_instructions = Some(format!("{PLAN_EXPLORE_PROMPT}\n\nFocus:\n- {focus}\n"));

    cfg.model = Some(
        parent_ctx
            .mini_subagent_model
            .clone()
            .unwrap_or_else(|| DEFAULT_MINI_SUBAGENT_MODEL_SLUG.to_string()),
    );
    invocation.model = cfg.model.clone();
    cfg.model_reasoning_effort = parent_ctx
        .mini_subagent_reasoning_effort
        .or(Some(codex_protocol::openai_models::ReasoningEffort::Medium));
    cfg.model_reasoning_summary = parent_ctx.client.get_reasoning_summary();

    let mut features = cfg.features.clone();
    crate::tasks::constrain_features_for_planning(&mut features);
    cfg.features = features;

    cfg.approval_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::AskForApproval::Never);
    cfg.sandbox_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::SandboxPolicy::ReadOnly);

    let input = vec![UserInput::Text {
        text: invocation.prompt.clone(),
    }];

    match crate::tools::subagent_runner::run_subagent_tool_call(
        parent_session,
        parent_ctx,
        call_id,
        invocation,
        cfg,
        input,
        SubAgentSource::Other(format!("plan_explore_{idx}")),
    )
    .await
    {
        Ok(response) => response,
        Err(err) => err,
    }
}

#[async_trait]
impl ToolHandler for PlanExploreHandler {
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
        let is_plan_mode = matches!(
            source,
            SessionSource::SubAgent(SubAgentSource::Other(label)) if label == "plan_mode"
        );
        if !is_plan_mode {
            return Err(FunctionCallError::RespondToModel(
                "plan_explore is only available in /plan mode".to_string(),
            ));
        }

        let args: PlanExploreArgs = serde_json::from_str(&arguments).map_err(|e| {
            FunctionCallError::RespondToModel(format!("failed to parse function arguments: {e:?}"))
        })?;

        let goal = args.goal.trim();
        if goal.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "goal must be non-empty".to_string(),
            ));
        }

        let base_config = turn.client.config().as_ref().clone();
        let goal = goal.to_string();

        let explorers = match args.explorers {
            Some(explorers) => {
                if explorers.is_empty() {
                    return Err(FunctionCallError::RespondToModel(
                        "explorers must be non-empty when provided".to_string(),
                    ));
                }
                explorers
            }
            None => (1..=DEFAULT_TOTAL_EXPLORERS)
                .map(|idx| ExplorerArgs {
                    focus: explorer_focus(idx).to_string(),
                    description: None,
                    prompt: None,
                })
                .collect(),
        };

        let total_explorers = explorers.len();

        let started_at = Instant::now();
        let mut join_set = JoinSet::new();
        for (zero_idx, explorer) in explorers.into_iter().enumerate() {
            let idx = zero_idx + 1;
            let focus = explorer.focus.trim().to_string();
            if focus.is_empty() {
                return Err(FunctionCallError::RespondToModel(format!(
                    "explorers[{zero_idx}] focus must be non-empty"
                )));
            }

            let description = explorer.description.map(|d| d.trim().to_string());
            let description = if description.as_deref().is_some_and(str::is_empty) {
                None
            } else {
                description
            };
            let description =
                description.unwrap_or_else(|| format!("{focus} ({idx}/{total_explorers})"));

            let prompt = explorer.prompt.map(|p| p.trim().to_string());
            let prompt = if prompt.as_deref().is_some_and(str::is_empty) {
                None
            } else {
                prompt
            };
            let prompt = prompt.unwrap_or_else(|| format!("Goal: {goal}\n\nFocus: {focus}"));

            let explorer_call_id = format!("{call_id}:plan_explore:{idx}");
            let explorer_invocation = SubAgentInvocation {
                description,
                label: format!("plan_explore_{idx}"),
                prompt,
                model: None,
            };
            let base_config = base_config.clone();
            let session = Arc::clone(&session);
            let turn = Arc::clone(&turn);
            let focus = focus.clone();
            join_set.spawn(async move {
                let out = run_one_explorer(
                    explorer_call_id,
                    explorer_invocation,
                    base_config,
                    idx,
                    focus.clone(),
                    session,
                    turn,
                )
                .await;
                (idx, focus, out)
            });
        }

        let mut reports_by_idx = vec![String::new(); total_explorers];
        let mut focus_by_idx = vec![String::new(); total_explorers];
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((idx, focus, out)) => {
                    if idx > 0 && idx <= total_explorers {
                        reports_by_idx[idx - 1] = out;
                        focus_by_idx[idx - 1] = focus;
                    }
                }
                Err(err) => {
                    return Err(FunctionCallError::RespondToModel(format!(
                        "failed to join plan exploration subagent: {err:?}"
                    )));
                }
            }
        }

        Ok(ToolOutput::Function {
            content: json!({
                "duration_ms": started_at.elapsed().as_millis(),
                "reports": reports_by_idx
                    .into_iter()
                    .zip(focus_by_idx)
                    .enumerate()
                    .map(|(i, (text, focus))| json!({
                        "idx": i + 1,
                        "focus": focus,
                        "text": text,
                    }))
                    .collect::<Vec<_>>(),
            })
            .to_string(),
            content_items: None,
            success: Some(true),
        })
    }
}
