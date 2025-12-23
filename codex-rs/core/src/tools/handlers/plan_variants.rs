use async_trait::async_trait;
use codex_protocol::plan_mode::PlanOutputEvent;
use codex_protocol::plan_tool::UpdatePlanArgs;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::user_input::UserInput;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
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

pub(crate) const PROPOSE_PLAN_VARIANTS_TOOL_NAME: &str = "propose_plan_variants";

pub struct PlanVariantsHandler;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposePlanVariantsArgs {
    goal: String,
}

const PLAN_VARIANT_PROMPT: &str = r#"You are a planning subagent producing a single plan variant for the user's goal.

Hard rules:
- Do not ask the user questions.
- Do not propose or perform edits. Do not call apply_patch.
- Do not call propose_plan_variants.
- You may explore the repo with read-only commands, but keep it minimal (2-6 targeted commands) and avoid dumping large files.
- If the `web_search` tool is available, you may use it sparingly for up-to-date or niche details; prefer repo-local sources and tolerate tool failures.
- Output ONLY valid JSON matching this shape:
  { "title": string, "summary": string, "plan": { "explanation": string|null, "plan": [ { "step": string, "status": "pending"|"in_progress"|"completed" } ] } }
  Do not wrap the JSON in markdown code fences.

Quality bar:
- Scale the number of steps to the task. Avoid filler (small: 4-8; typical: 8-12; complex: 12-16).
- In `summary`, state when to choose this variant and the biggest trade-off.
- `plan.explanation` MUST be a practical runbook with clear section headings. Keep it concise and focus on what makes this variant distinct. Include ALL of:
  - Assumptions
  - Scope (in-scope + non-goals)
  - Touchpoints (files/modules/components to change, with what/why)
  - Approach (sequence notes; include a short "discovery checklist" of 2-6 read-only commands/files if the task is ambiguous)
  - Risks (failure modes + mitigations + rollback)
  - Acceptance criteria (observable outcomes; 3-8 bullets)
  - Validation (exact commands, and where to run them)
  - Open questions (optional; write "None." if none)
- Make this variant meaningfully different from other plausible variants (trade-offs, sequencing, scope, risk posture).
"#;

fn variant_name(idx: usize, total: usize) -> Option<&'static str> {
    if total == 3 {
        match idx {
            1 => Some("Minimal"),
            2 => Some("Correctness"),
            3 => Some("DX"),
            _ => None,
        }
    } else {
        None
    }
}

fn variant_title(idx: usize, total: usize) -> String {
    variant_name(idx, total)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if total > 0 {
                format!("Variant {idx}/{total}")
            } else {
                format!("Variant {idx}")
            }
        })
}

fn plan_variant_focus(idx: usize) -> &'static str {
    match idx {
        1 => {
            "Variant 1 (Minimal): minimal-risk, minimal-diff path (pragmatic, incremental; avoid refactors)."
        }
        2 => {
            "Variant 2 (Correctness): correctness-first path (tests, invariants, edge cases, careful validation/rollback)."
        }
        3 => {
            "Variant 3 (DX): architecture/DX-first path (refactors that pay down tech debt, clearer abstractions, better ergonomics)."
        }
        _ => "Use a distinct angle and trade-offs.",
    }
}

fn strip_clarification_policy(existing: &str) -> String {
    const HEADER: &str = "## Clarification Policy";
    let Some(start) = existing.find(HEADER) else {
        return existing.to_string();
    };

    let after_header = &existing[start + HEADER.len()..];
    let end_rel = after_header.find("\n## ").unwrap_or(after_header.len());
    let end = start + HEADER.len() + end_rel;

    let before = existing[..start].trim_end();
    let after = existing[end..].trim_start();
    if before.is_empty() {
        return after.to_string();
    }
    if after.is_empty() {
        return before.to_string();
    }
    format!("{before}\n{after}")
}

fn build_plan_variant_developer_instructions(idx: usize, total: usize, existing: &str) -> String {
    let existing = strip_clarification_policy(existing);
    let existing = existing.trim();
    if existing.is_empty() {
        return format!(
            "{PLAN_VARIANT_PROMPT}\n\n{focus}\n(Return plan variant {idx}/{total}.)",
            focus = plan_variant_focus(idx)
        );
    }
    format!(
        "{PLAN_VARIANT_PROMPT}\n\n{focus}\n(Return plan variant {idx}/{total}.)\n\n{existing}",
        focus = plan_variant_focus(idx)
    )
}

#[async_trait]
impl ToolHandler for PlanVariantsHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            payload,
            tool_name,
            ..
        } = invocation;

        let source = turn.client.get_session_source();
        if let SessionSource::SubAgent(SubAgentSource::Other(label)) = &source
            && label.starts_with("plan_variant")
        {
            return Err(FunctionCallError::RespondToModel(
                "propose_plan_variants is not supported in plan-variant subagents".to_string(),
            ));
        }

        let ToolPayload::Function { arguments } = payload else {
            return Err(FunctionCallError::RespondToModel(format!(
                "unsupported payload for {tool_name}"
            )));
        };

        let args: ProposePlanVariantsArgs = serde_json::from_str(&arguments).map_err(|e| {
            FunctionCallError::RespondToModel(format!("failed to parse function arguments: {e:?}"))
        })?;

        let goal = args.goal.trim();
        if goal.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "goal must be non-empty".to_string(),
            ));
        }

        const TOTAL: usize = 3;

        let mut join_set = JoinSet::new();
        for idx in 1..=TOTAL {
            let label = format!("plan_variant_{idx}");
            let base_config = turn.client.config().as_ref().clone();
            let goal = goal.to_string();
            let session = Arc::clone(&session);
            let turn = Arc::clone(&turn);
            join_set.spawn(async move {
                let started_at = Instant::now();

                session
                    .notify_background_event(
                        turn.as_ref(),
                        format!("Plan variants: generating {idx}/{TOTAL}"),
                    )
                    .await;

                session
                    .notify_background_event(
                        turn.as_ref(),
                        format!("Plan variant {idx}/{TOTAL}: starting"),
                    )
                    .await;

                let out = run_one_variant(
                    base_config,
                    goal,
                    idx,
                    TOTAL,
                    label,
                    Arc::clone(&session),
                    Arc::clone(&turn),
                )
                .await;

                let elapsed = started_at.elapsed();
                session
                    .notify_background_event(
                        turn.as_ref(),
                        format!(
                            "Plan variants: finished {idx}/{TOTAL} ({})",
                            fmt_variant_duration(elapsed)
                        ),
                    )
                    .await;

                (idx, out)
            });
        }

        let mut variants_by_idx = vec![None; TOTAL];
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((idx, out)) => {
                    if idx > 0 && idx <= TOTAL {
                        variants_by_idx[idx - 1] = Some(out);
                    }
                }
                Err(err) => {
                    return Err(FunctionCallError::RespondToModel(format!(
                        "failed to join planning subagent task: {err:?}"
                    )));
                }
            }
        }

        let variants = variants_by_idx
            .into_iter()
            .enumerate()
            .map(|(idx, out)| {
                out.unwrap_or_else(|| PlanOutputEvent {
                    title: variant_title(idx + 1, TOTAL),
                    summary: "Variant task did not return output.".to_string(),
                    plan: UpdatePlanArgs {
                        explanation: None,
                        plan: Vec::new(),
                    },
                })
            })
            .collect::<Vec<_>>();

        Ok(ToolOutput::Function {
            content: json!({ "variants": variants }).to_string(),
            content_items: None,
            success: Some(true),
        })
    }
}

fn fmt_variant_duration(elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64();
    if secs < 60.0 {
        return format!("{secs:.1}s");
    }

    let whole_secs = elapsed.as_secs();
    let minutes = whole_secs / 60;
    let seconds = whole_secs % 60;
    format!("{minutes}m {seconds:02}s")
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

fn fmt_variant_tokens(tokens: i64) -> Option<String> {
    if tokens <= 0 {
        return None;
    }

    let tokens_f = tokens as f64;
    if tokens < 1_000 {
        return Some(format!("{tokens}"));
    }
    if tokens < 100_000 {
        return Some(format!("{:.1}k", tokens_f / 1_000.0));
    }
    if tokens < 1_000_000 {
        return Some(format!("{}k", tokens / 1_000));
    }
    if tokens < 100_000_000 {
        return Some(format!("{:.1}M", tokens_f / 1_000_000.0));
    }

    Some(format!("{}M", tokens / 1_000_000))
}

async fn run_one_variant(
    base_config: Config,
    goal: String,
    idx: usize,
    total: usize,
    label: String,
    parent_session: Arc<crate::codex::Session>,
    parent_ctx: Arc<crate::codex::TurnContext>,
) -> PlanOutputEvent {
    let mut cfg = base_config.clone();

    // Do not override the base/system prompt; some environments restrict it to whitelisted prompts.
    // Put plan-variant guidance in developer instructions instead.
    //
    // Also avoid inheriting large caller developer instructions (e.g. plan mode's own instructions)
    // into each variant, which can significantly increase token usage. Plan variants use a focused
    // prompt and return JSON only.
    cfg.developer_instructions = Some(build_plan_variant_developer_instructions(idx, total, ""));

    // Keep plan variants on the same model + reasoning settings as the parent turn, unless a
    // plan-model override is configured.
    cfg.model = Some(
        parent_ctx
            .plan_model
            .clone()
            .unwrap_or_else(|| parent_ctx.client.get_model()),
    );
    cfg.model_reasoning_effort = parent_ctx
        .plan_reasoning_effort
        .or(parent_ctx.client.get_reasoning_effort());
    cfg.model_reasoning_summary = parent_ctx.client.get_reasoning_summary();

    let mut features = cfg.features.clone();
    crate::tasks::constrain_features_for_planning(&mut features);
    cfg.features = features;
    cfg.approval_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::AskForApproval::Never);
    cfg.sandbox_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::SandboxPolicy::ReadOnly);

    let input = vec![UserInput::Text {
        text: format!("Goal: {goal}\n\nReturn plan variant #{idx}."),
    }];

    let cancel = CancellationToken::new();
    let session_for_events = Arc::clone(&parent_session);
    let io = match run_codex_conversation_one_shot(
        cfg,
        Arc::clone(&parent_session.services.auth_manager),
        Arc::clone(&parent_session.services.models_manager),
        input,
        parent_session,
        Arc::clone(&parent_ctx),
        cancel,
        None,
        SubAgentSource::Other(label),
    )
    .await
    {
        Ok(io) => io,
        Err(err) => {
            return PlanOutputEvent {
                title: variant_title(idx, total),
                summary: format!("Failed to start subagent: {err}"),
                plan: UpdatePlanArgs {
                    explanation: None,
                    plan: Vec::new(),
                },
            };
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

            if should_report && let Some(formatted) = fmt_variant_tokens(tokens) {
                session_for_events
                    .notify_background_event(
                        parent_ctx.as_ref(),
                        format!("Plan variant {idx}/{total}: tokens {formatted}"),
                    )
                    .await;
                last_reported_tokens = Some(tokens);
                last_token_update_at = Some(now);
            }
        }

        if let Some(activity) = activity_for_event(&msg)
            && last_activity.as_deref() != Some(activity.as_str())
        {
            session_for_events
                .notify_background_event(
                    parent_ctx.as_ref(),
                    format!("Plan variant {idx}/{total}: {activity}"),
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

    let text = last_agent_message.unwrap_or_default();
    parse_plan_output_event(idx, total, text.as_str())
}

fn parse_plan_output_event(idx: usize, total: usize, text: &str) -> PlanOutputEvent {
    if let Ok(mut ev) = serde_json::from_str::<PlanOutputEvent>(text) {
        ev.title = variant_title(idx, total);
        return ev;
    }
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}'))
        && start < end
        && let Some(slice) = text.get(start..=end)
        && let Ok(mut ev) = serde_json::from_str::<PlanOutputEvent>(slice)
    {
        ev.title = variant_title(idx, total);
        return ev;
    }
    PlanOutputEvent {
        title: variant_title(idx, total),
        summary: "Subagent did not return valid JSON.".to_string(),
        plan: UpdatePlanArgs {
            explanation: Some(text.to_string()),
            plan: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_activity_command_strips_powershell_wrapper() {
        let shell = if cfg!(windows) {
            "C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        } else {
            "/usr/local/bin/powershell.exe"
        };
        let cmd = vec![
            shell.to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "rg --version".to_string(),
        ];
        assert_eq!(fmt_exec_activity_command(&cmd), "rg --version");
    }

    #[test]
    fn exec_activity_command_strips_bash_lc_wrapper() {
        let cmd = vec![
            "bash".to_string(),
            "-lc".to_string(),
            "rg --version".to_string(),
        ];
        assert_eq!(fmt_exec_activity_command(&cmd), "rg --version");
    }

    #[test]
    fn plan_variant_titles_are_stable() {
        assert_eq!(variant_title(1, 3), "Minimal");
        assert_eq!(variant_title(2, 3), "Correctness");
        assert_eq!(variant_title(3, 3), "DX");
        assert_eq!(variant_title(4, 3), "Variant 4/3");
        assert_eq!(variant_title(1, 2), "Variant 1/2");
    }

    #[test]
    fn plan_variants_strip_clarification_policy_from_existing_instructions() {
        let existing =
            "## Clarification Policy\n- Ask questions\n\n## Something Else\nKeep this.\n";
        let out = build_plan_variant_developer_instructions(1, 3, existing);
        assert!(!out.contains("## Clarification Policy"));
        assert!(out.contains("## Something Else"));
        assert!(out.contains("Keep this."));
    }

    #[test]
    fn plan_variant_output_titles_are_normalized() {
        let ev = parse_plan_output_event(
            2,
            3,
            r#"{ "title": "Something else", "summary": "ok", "plan": { "explanation": null, "plan": [] } }"#,
        );
        assert_eq!(ev.title, "Correctness");
    }

    #[tokio::test]
    async fn plan_variants_do_not_override_base_instructions() {
        let codex_home = tempfile::TempDir::new().expect("tmp dir");
        let overrides = {
            #[cfg(target_os = "linux")]
            {
                use assert_cmd::cargo::cargo_bin;
                crate::config::ConfigOverrides {
                    codex_linux_sandbox_exe: Some(cargo_bin("codex-linux-sandbox")),
                    ..Default::default()
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                crate::config::ConfigOverrides::default()
            }
        };
        let mut cfg = crate::config::ConfigBuilder::default()
            .codex_home(codex_home.path().to_path_buf())
            .harness_overrides(overrides)
            .build()
            .await
            .expect("load test config");

        cfg.base_instructions = None;
        cfg.developer_instructions = Some("existing developer instructions".to_string());

        let existing_base = cfg.base_instructions.clone();
        let existing = cfg.developer_instructions.clone().unwrap_or_default();
        cfg.developer_instructions = Some(build_plan_variant_developer_instructions(
            1,
            3,
            existing.as_str(),
        ));

        assert_eq!(cfg.base_instructions, existing_base);
        assert!(
            cfg.developer_instructions
                .as_deref()
                .unwrap_or_default()
                .starts_with("You are a planning subagent")
        );
        assert!(
            cfg.developer_instructions
                .as_deref()
                .unwrap_or_default()
                .contains("existing developer instructions")
        );
    }

    #[test]
    fn plan_variants_require_explanation_sections() {
        let required = [
            "Assumptions",
            "Scope (in-scope + non-goals)",
            "Touchpoints (files/modules/components to change, with what/why)",
            "Approach (sequence notes; include a short \"discovery checklist\" of 2-6 read-only commands/files if the task is ambiguous)",
            "Risks (failure modes + mitigations + rollback)",
            "Acceptance criteria (observable outcomes; 3-8 bullets)",
            "Validation (exact commands, and where to run them)",
        ];

        for needle in required {
            assert!(
                PLAN_VARIANT_PROMPT.contains(needle),
                "missing required section anchor: {needle}"
            );
        }
    }
}
