use async_trait::async_trait;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentInvocation;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::SubAgentToolCallActivityEvent;
use codex_protocol::protocol::SubAgentToolCallBeginEvent;
use codex_protocol::protocol::SubAgentToolCallEndEvent;
use codex_protocol::protocol::SubAgentToolCallTokensEvent;
use codex_protocol::user_input::UserInput;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::codex_delegate::run_codex_conversation_one_shot;
use crate::config::Config;
use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub(crate) const PLAN_EXPLORE_TOOL_NAME: &str = "plan_explore";

pub struct PlanExploreHandler;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanExploreArgs {
    goal: String,
}

const TOTAL_EXPLORERS: usize = 3;

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

struct CancelOnDrop {
    token: CancellationToken,
}

impl CancelOnDrop {
    fn new(token: CancellationToken) -> Self {
        Self { token }
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

fn fmt_exec_activity_command(command: &[String]) -> String {
    if command.is_empty() {
        return "shell".to_string();
    }

    let cmd = if let Some((_shell, script)) = crate::parse_command::extract_shell_command(command) {
        let script = script.trim();
        if script.is_empty() {
            "shell".to_string()
        } else {
            script
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        }
    } else {
        crate::parse_command::shlex_join(command)
    };

    if cmd.is_empty() {
        "shell".to_string()
    } else {
        cmd
    }
}

fn activity_for_event(msg: &EventMsg) -> Option<String> {
    match msg {
        EventMsg::TaskStarted(_) => Some("starting".to_string()),
        EventMsg::UserMessage(_) => Some("sending prompt".to_string()),
        EventMsg::AgentReasoning(_)
        | EventMsg::AgentReasoningDelta(_)
        | EventMsg::AgentReasoningRawContent(_)
        | EventMsg::AgentReasoningRawContentDelta(_)
        | EventMsg::AgentReasoningSectionBreak(_) => Some("thinking".to_string()),
        EventMsg::AgentMessage(_) | EventMsg::AgentMessageDelta(_) => Some("writing".to_string()),
        EventMsg::ExecCommandBegin(ev) => Some(fmt_exec_activity_command(&ev.command)),
        EventMsg::McpToolCallBegin(ev) => Some(format!(
            "mcp {}/{}",
            ev.invocation.server.trim(),
            ev.invocation.tool.trim()
        )),
        EventMsg::WebSearchBegin(_) => Some("web_search".to_string()),
        _ => None,
    }
}

async fn run_one_explorer(
    call_id: String,
    invocation: SubAgentInvocation,
    base_config: Config,
    goal: String,
    idx: usize,
    parent_session: Arc<crate::codex::Session>,
    parent_ctx: Arc<crate::codex::TurnContext>,
) -> String {
    let focus = explorer_focus(idx);
    let started_at = Instant::now();

    let mut cfg = base_config;

    // Keep this prompt focused and small; avoid inheriting large caller developer instructions.
    cfg.developer_instructions = Some(format!("{PLAN_EXPLORE_PROMPT}\n\nFocus:\n- {focus}\n"));

    cfg.model = Some(parent_ctx.client.get_model());
    cfg.model_reasoning_effort = parent_ctx.client.get_reasoning_effort();
    cfg.model_reasoning_summary = parent_ctx.client.get_reasoning_summary();

    let mut features = cfg.features.clone();
    crate::tasks::constrain_features_for_planning(&mut features);
    cfg.features = features;

    cfg.approval_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::AskForApproval::Never);
    cfg.sandbox_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::SandboxPolicy::ReadOnly);

    let input = vec![UserInput::Text {
        text: format!("Goal: {goal}\n\nFocus: {focus}"),
    }];

    parent_session
        .send_event(
            parent_ctx.as_ref(),
            EventMsg::SubAgentToolCallBegin(SubAgentToolCallBeginEvent {
                call_id: call_id.clone(),
                invocation: invocation.clone(),
            }),
        )
        .await;
    parent_session
        .send_event(
            parent_ctx.as_ref(),
            EventMsg::SubAgentToolCallActivity(SubAgentToolCallActivityEvent {
                call_id: call_id.clone(),
                activity: "starting".to_string(),
            }),
        )
        .await;

    let cancel = parent_session
        .turn_cancellation_token(&parent_ctx.sub_id)
        .await
        .map_or_else(CancellationToken::new, |token| token.child_token());
    let _cancel_guard = CancelOnDrop::new(cancel.clone());
    let io = match run_codex_conversation_one_shot(
        cfg,
        Arc::clone(&parent_session.services.auth_manager),
        Arc::clone(&parent_session.services.models_manager),
        input,
        Arc::clone(&parent_session),
        Arc::clone(&parent_ctx),
        cancel,
        None,
        SubAgentSource::Other(format!("plan_explore_{idx}")),
    )
    .await
    {
        Ok(io) => io,
        Err(err) => {
            let message = format!("failed to start explorer {idx}/{TOTAL_EXPLORERS}: {err}");
            parent_session
                .send_event(
                    parent_ctx.as_ref(),
                    EventMsg::SubAgentToolCallEnd(SubAgentToolCallEndEvent {
                        call_id,
                        invocation,
                        duration: started_at.elapsed(),
                        tokens: None,
                        result: Err(message.clone()),
                    }),
                )
                .await;
            return message;
        }
    };

    let mut last_agent_message: Option<String> = None;
    let mut last_activity: Option<String> = None;
    let mut last_reported_tokens: Option<i64> = None;
    let mut last_token_update_at: Option<Instant> = None;
    while let Ok(Event { msg, .. }) = io.rx_event.recv().await {
        if let EventMsg::TokenCount(ev) = &msg
            && let Some(info) = &ev.info
        {
            let tokens = info.total_token_usage.blended_total();
            let now = Instant::now();
            let should_report = match (last_reported_tokens, last_token_update_at) {
                (Some(prev), Some(prev_at)) => {
                    tokens > prev
                        && (tokens - prev >= 250 || now.duration_since(prev_at).as_secs() >= 2)
                }
                (Some(prev), None) => tokens > prev,
                (None, _) => tokens > 0,
            };

            if should_report {
                parent_session
                    .send_event(
                        parent_ctx.as_ref(),
                        EventMsg::SubAgentToolCallTokens(SubAgentToolCallTokensEvent {
                            call_id: call_id.clone(),
                            tokens,
                        }),
                    )
                    .await;
                last_reported_tokens = Some(tokens);
                last_token_update_at = Some(now);
            }
        }

        if let Some(activity) = activity_for_event(&msg)
            && last_activity.as_deref() != Some(activity.as_str())
        {
            parent_session
                .send_event(
                    parent_ctx.as_ref(),
                    EventMsg::SubAgentToolCallActivity(SubAgentToolCallActivityEvent {
                        call_id: call_id.clone(),
                        activity: activity.clone(),
                    }),
                )
                .await;
            last_activity = Some(activity);
        }

        match msg {
            EventMsg::TaskComplete(ev) => {
                last_agent_message = ev.last_agent_message;
                break;
            }
            EventMsg::TurnAborted(_) => break,
            _ => {}
        }
    }

    parent_session
        .send_event(
            parent_ctx.as_ref(),
            EventMsg::SubAgentToolCallEnd(SubAgentToolCallEndEvent {
                call_id,
                invocation,
                duration: started_at.elapsed(),
                tokens: last_reported_tokens,
                result: Ok(last_agent_message.clone().unwrap_or_default()),
            }),
        )
        .await;

    last_agent_message.unwrap_or_default()
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

        let mut join_set = JoinSet::new();
        let started_at = Instant::now();
        for idx in 1..=TOTAL_EXPLORERS {
            let explorer_call_id = format!("{call_id}:plan_explore:{idx}");
            let explorer_invocation = SubAgentInvocation {
                description: format!(
                    "Plan explore {idx}/{TOTAL_EXPLORERS}: {}",
                    explorer_focus(idx)
                ),
                label: format!("plan_explore_{idx}"),
                prompt: format!("Goal: {goal}\n\nFocus: {}", explorer_focus(idx)),
            };
            let base_config = base_config.clone();
            let goal = goal.clone();
            let session = Arc::clone(&session);
            let turn = Arc::clone(&turn);
            join_set.spawn(async move {
                let out = run_one_explorer(
                    explorer_call_id,
                    explorer_invocation,
                    base_config,
                    goal,
                    idx,
                    session,
                    turn,
                )
                .await;
                (idx, out)
            });
        }

        let mut reports_by_idx = vec![String::new(); TOTAL_EXPLORERS];
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((idx, out)) => {
                    if idx > 0 && idx <= TOTAL_EXPLORERS {
                        reports_by_idx[idx - 1] = out;
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
                    .enumerate()
                    .map(|(i, text)| json!({
                        "idx": i + 1,
                        "focus": explorer_focus(i + 1),
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
