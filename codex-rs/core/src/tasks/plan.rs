use async_trait::async_trait;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::AgentMessageContentDeltaEvent;
use codex_protocol::protocol::AgentMessageDeltaEvent;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ExitedPlanModeEvent;
use codex_protocol::protocol::ItemCompletedEvent;
use codex_protocol::protocol::PlanOutputEvent;
use codex_protocol::protocol::PlanRequest;
use codex_protocol::protocol::SubAgentSource;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::codex_delegate::run_codex_conversation_one_shot;
use crate::plan_output;
use crate::project_internal_paths;
use crate::state::TaskKind;
use codex_protocol::user_input::UserInput;
use std::path::Path;
use std::sync::Arc;

use super::SessionTask;
use super::SessionTaskContext;

#[derive(Clone)]
pub(crate) struct PlanTask {
    request: PlanRequest,
}

impl PlanTask {
    pub(crate) fn new(request: PlanRequest) -> Self {
        Self { request }
    }
}

const PLAN_MODE_DEVELOPER_INSTRUCTIONS: &str = r#"## Plan Mode
You are planning only. Do not call `apply_patch` or execute mutating commands.

Output quality bar:
- The plan must be actionable by another engineer without extra back-and-forth.
- Scale the number of steps to the task. Avoid filler (small: 4-8; typical: 8-12; complex: 12-16).
- Each step should describe a concrete deliverable and, when helpful, name key files/components to touch.
- Put detailed substeps, rationale, trade-offs, risks, and validation commands in `plan.explanation` (multi-paragraph is fine).
- `plan.explanation` MUST be a practical runbook. Use clear section headings. Include ALL of:
  - Assumptions
  - Scope (in-scope + non-goals)
  - Touchpoints (files/modules/components to change, with what/why)
  - Approach (sequence notes; include a short "discovery checklist" of 2-6 read-only commands/files if the task is ambiguous)
  - Optional: Web search (only if available; keep it minimal and tolerate failures)
  - Risks (failure modes + mitigations + rollback)
  - Acceptance criteria (observable outcomes; 3-8 bullets)
  - Validation (exact commands, and where to run them)
  - Open questions (optional; write "None." if none)
  - If the task involves UI (web, mobile, TUI), add an explicit "UI quality bar" subsection under Approach or Acceptance criteria that covers:
    - Visual/UX goals (what should feel better, not just what changes)
    - Design system plan (tokens, spacing, typography, component reuse)
    - Responsiveness (breakpoints, layout constraints) and accessibility (keyboard, contrast, screen readers where applicable)
    - Interaction polish (loading/empty/error states, animations/micro-interactions only if appropriate)
    - Verification: how to manually validate the UX (exact steps) plus any automated UI tests to run

Mini-example (illustrative; do not copy verbatim):
- Step: "Add `--dry-run` flag to CLI"
- Touchpoints: `src/cli.rs` (arg parsing), `src/main.rs` (plumb flag)
- Acceptance criteria: "`mytool --dry-run` prints planned actions and exits 0 without writing"
- Validation: "`cd mytool; cargo test -p mytool-cli`"

Process:
- If you need repo grounding (unclear entry points / touchpoints), call `plan_explore` once early.
- Once you understand the goal, call `propose_plan_variants` to generate 3 alternative plans (at most once per draft).
- Synthesize the final plan (do not just pick a variant verbatim).
- Present the final plan via `approve_plan`.
- After an `approve_plan` result:
  - Approved: output the final plan JSON as your only assistant message.
  - Revised: incorporate feedback and call `approve_plan` again.
  - Rejected: stop; do not proceed.
"#;

const PLAN_MODE_DEVELOPER_PREFIX: &str = r#"## Plan Mode (Slash Command)
Goal: produce a clear, actionable implementation plan for the user's request without making code changes.

Rules:
- You may explore the repo with read-only commands, but keep it minimal (2-6 targeted commands) and avoid dumping large files.
- If the `web_search` tool is available, you may use it sparingly for up-to-date or niche details; prefer repo-local sources and tolerate tool failures.
- Do not attempt to edit files or run mutating commands (no installs, no git writes, no redirects/heredocs that write files).
- When the goal is ambiguous in a way that would change the plan materially, ask clarifying questions via AskUserQuestion instead of guessing. Batch questions and avoid prolonged back-and-forth.
- If you would otherwise run more than 1-2 repo exploration commands (e.g., `rg`/`ls`/reading files) to get grounded, call `plan_explore` once early instead.
- Use `propose_plan_variants` to generate 3 alternative plans as input (at most once per plan draft). If it fails, proceed without it.
- When you have a final plan, call `approve_plan` with:
  - Title: short and specific.
  - Summary: 2-4 sentences with key approach + scope boundaries.
  - Steps: concise, ordered, and checkable.
  - Steps status: set every step status to `"pending"` (this is an approved plan, not execution progress).
  - Explanation: use the required section headings (Assumptions; Scope; Touchpoints; Approach; Risks; Acceptance criteria; Validation; Open questions) and make it a junior-executable runbook. For headings that don't apply, write "None.".
- If the user requests revisions, incorporate feedback and propose a revised plan (you may call `propose_plan_variants` again only if the plan materially changes or the user asks for alternatives).
- If the user rejects, stop.

When the plan is approved, your final assistant message MUST be ONLY valid JSON matching:
{ "title": string, "summary": string, "plan": { "explanation": string|null, "plan": [ { "step": string, "status": "pending"|"in_progress"|"completed" } ] } }
Do not wrap the JSON in markdown code fences.
"#;

pub(crate) fn constrain_features_for_planning(features: &mut crate::features::Features) {
    features
        .disable(crate::features::Feature::ApplyPatchFreeform)
        .disable(crate::features::Feature::ViewImageTool);
}

fn build_plan_mode_developer_instructions(existing: &str, ask: &str) -> String {
    let mut developer_instructions = String::new();
    developer_instructions.push_str(PLAN_MODE_DEVELOPER_PREFIX);
    developer_instructions.push_str("\n\n");
    developer_instructions.push_str(PLAN_MODE_DEVELOPER_INSTRUCTIONS);

    let ask = ask.trim();
    if !ask.is_empty() {
        developer_instructions.push('\n');
        developer_instructions.push_str(ask);
    }

    let existing = existing.trim();
    if !existing.is_empty() {
        developer_instructions.push_str("\n\n");
        developer_instructions.push_str(existing);
    }

    developer_instructions
}

#[async_trait]
impl SessionTask for PlanTask {
    fn kind(&self) -> TaskKind {
        TaskKind::Plan
    }

    async fn run(
        self: Arc<Self>,
        session: Arc<SessionTaskContext>,
        ctx: Arc<TurnContext>,
        _input: Vec<UserInput>,
        cancellation_token: CancellationToken,
    ) -> Option<String> {
        let output = match start_plan_conversation(
            session.clone(),
            ctx.clone(),
            self.request.clone(),
            cancellation_token.clone(),
        )
        .await
        {
            Some(receiver) => process_plan_events(session.clone(), ctx.clone(), receiver).await,
            None => None,
        };

        if !cancellation_token.is_cancelled() {
            exit_plan_mode(session.clone_session(), output.clone(), ctx.clone()).await;
        }
        None
    }

    async fn abort(&self, session: Arc<SessionTaskContext>, ctx: Arc<TurnContext>) {
        exit_plan_mode(session.clone_session(), None, ctx).await;
    }
}

async fn start_plan_conversation(
    session: Arc<SessionTaskContext>,
    ctx: Arc<TurnContext>,
    request: PlanRequest,
    cancellation_token: CancellationToken,
) -> Option<async_channel::Receiver<Event>> {
    let config = ctx.client.config();
    let mut sub_agent_config = config.as_ref().clone();

    // Ensure plan mode uses the same model + reasoning settings as the parent turn (e.g. after a
    // `/model` change), unless a plan-model override is configured. The base config can lag behind
    // session model overrides.
    sub_agent_config.model = Some(
        ctx.plan_model
            .clone()
            .unwrap_or_else(|| ctx.client.get_model()),
    );
    sub_agent_config.model_reasoning_effort = ctx
        .plan_reasoning_effort
        .or(ctx.client.get_reasoning_effort());
    sub_agent_config.model_reasoning_summary = ctx.client.get_reasoning_summary();

    let ask = crate::tools::spec::prepend_ask_user_question_developer_instructions(None)
        .unwrap_or_default();

    // Plan mode must not override the base/system prompt because some environments restrict it to
    // whitelisted prompts. Instead, prepend plan mode guidance to developer instructions.
    let existing = sub_agent_config
        .developer_instructions
        .clone()
        .unwrap_or_default();
    let developer_instructions =
        build_plan_mode_developer_instructions(existing.as_str(), ask.as_str());
    sub_agent_config.developer_instructions =
        crate::tools::spec::prepend_clarification_policy_developer_instructions(Some(
            developer_instructions,
        ));

    constrain_features_for_planning(&mut sub_agent_config.features);

    sub_agent_config.approval_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::AskForApproval::Never);
    sub_agent_config.sandbox_policy =
        crate::config::Constrained::allow_any(codex_protocol::protocol::SandboxPolicy::ReadOnly);

    let input: Vec<UserInput> = vec![UserInput::Text {
        text: format!("User goal: {}", request.goal.trim()),
    }];

    run_codex_conversation_one_shot(
        sub_agent_config,
        session.auth_manager(),
        session.models_manager(),
        input,
        session.clone_session(),
        ctx,
        cancellation_token,
        None,
        SubAgentSource::Other("plan_mode".to_string()),
    )
    .await
    .ok()
    .map(|io| io.rx_event)
}

async fn process_plan_events(
    session: Arc<SessionTaskContext>,
    ctx: Arc<TurnContext>,
    receiver: async_channel::Receiver<Event>,
) -> Option<PlanOutputEvent> {
    while let Ok(event) = receiver.recv().await {
        match event.clone().msg {
            // Suppress assistant text; plan mode surfaces via tool UIs and final output.
            EventMsg::AgentMessage(_)
            | EventMsg::ItemCompleted(ItemCompletedEvent {
                item: TurnItem::AgentMessage(_),
                ..
            })
            | EventMsg::AgentMessageDelta(AgentMessageDeltaEvent { .. })
            | EventMsg::AgentMessageContentDelta(AgentMessageContentDeltaEvent { .. }) => {}
            EventMsg::TaskComplete(task_complete) => {
                let out = task_complete
                    .last_agent_message
                    .as_deref()
                    .and_then(parse_plan_output_event);
                return out;
            }
            EventMsg::TurnAborted(_) => return None,
            other => {
                session
                    .clone_session()
                    .send_event(ctx.as_ref(), other)
                    .await;
            }
        }
    }
    None
}

fn parse_plan_output_event(text: &str) -> Option<PlanOutputEvent> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return None;
    }
    if let Ok(ev) = serde_json::from_str::<PlanOutputEvent>(trimmed) {
        return Some(ev);
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}'))
        && start < end
        && let Some(slice) = trimmed.get(start..=end)
        && let Ok(ev) = serde_json::from_str::<PlanOutputEvent>(slice)
    {
        return Some(ev);
    }
    None
}

pub(crate) async fn exit_plan_mode(
    session: Arc<Session>,
    plan_output: Option<PlanOutputEvent>,
    ctx: Arc<TurnContext>,
) {
    const PLAN_USER_MESSAGE_ID: &str = "plan:rollout:user";
    const PLAN_ASSISTANT_MESSAGE_ID: &str = "plan:rollout:assistant";

    session.set_pending_approved_plan(plan_output.clone()).await;
    if let Some(out) = plan_output.as_ref()
        && let Err(err) = persist_approved_plan_markdown(out, &ctx.cwd).await
    {
        warn!("failed to write approved plan markdown: {err}");
    }

    let (user_message, assistant_message) = match plan_output.as_ref() {
        Some(out) => (
            "Plan approved.".to_string(),
            plan_output::render_approved_plan_transcript(out),
        ),
        None => (
            "Plan ended without an approved plan.".to_string(),
            "Plan was rejected or interrupted.".to_string(),
        ),
    };

    session
        .record_conversation_items(
            &ctx,
            &[ResponseItem::Message {
                id: Some(PLAN_USER_MESSAGE_ID.to_string()),
                role: "user".to_string(),
                content: vec![ContentItem::InputText { text: user_message }],
            }],
        )
        .await;
    session
        .send_event(
            ctx.as_ref(),
            EventMsg::ExitedPlanMode(ExitedPlanModeEvent { plan_output }),
        )
        .await;
    session
        .record_response_item_and_emit_turn_item(
            ctx.as_ref(),
            ResponseItem::Message {
                id: Some(PLAN_ASSISTANT_MESSAGE_ID.to_string()),
                role: "assistant".to_string(),
                content: vec![ContentItem::OutputText {
                    text: assistant_message,
                }],
            },
        )
        .await;
}

async fn persist_approved_plan_markdown(
    out: &PlanOutputEvent,
    cwd: &Path,
) -> Result<(), std::io::Error> {
    let path = project_internal_paths::approved_plan_markdown_path(cwd);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, plan_output::render_approved_plan_markdown(out)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::plan_tool::PlanItemArg;
    use codex_protocol::plan_tool::StepStatus;
    use codex_protocol::plan_tool::UpdatePlanArgs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn plan_mode_does_not_override_base_instructions() {
        // This test guards against regressions where plan mode sets custom base/system prompts,
        // which can break in environments that restrict system prompts.
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

        let ask = crate::tools::spec::prepend_ask_user_question_developer_instructions(None)
            .unwrap_or_default();
        let existing_base = cfg.base_instructions.clone();

        let existing = cfg.developer_instructions.clone().unwrap_or_default();
        let developer_instructions =
            build_plan_mode_developer_instructions(existing.as_str(), ask.as_str());
        cfg.developer_instructions =
            crate::tools::spec::prepend_clarification_policy_developer_instructions(Some(
                developer_instructions,
            ));

        assert_eq!(cfg.base_instructions, existing_base);
        assert!(
            cfg.developer_instructions
                .as_deref()
                .unwrap_or_default()
                .contains("## Plan Mode")
        );
        assert!(
            cfg.developer_instructions
                .as_deref()
                .unwrap_or_default()
                .contains("## Clarification Policy")
        );
        assert!(
            cfg.developer_instructions
                .as_deref()
                .unwrap_or_default()
                .contains("existing developer instructions")
        );
    }

    #[test]
    fn plan_mode_requires_explanation_sections() {
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
                PLAN_MODE_DEVELOPER_INSTRUCTIONS.contains(needle),
                "missing required section anchor: {needle}"
            );
        }

        assert!(PLAN_MODE_DEVELOPER_PREFIX.contains(
            "Assumptions; Scope; Touchpoints; Approach; Risks; Acceptance criteria; Validation"
        ));
    }

    #[test]
    fn planning_constraints_keep_web_search_if_enabled() {
        let mut features = crate::features::Features::with_defaults();
        features
            .enable(crate::features::Feature::ApplyPatchFreeform)
            .enable(crate::features::Feature::ViewImageTool)
            .enable(crate::features::Feature::WebSearchRequest);

        constrain_features_for_planning(&mut features);

        assert!(!features.enabled(crate::features::Feature::ApplyPatchFreeform));
        assert!(!features.enabled(crate::features::Feature::ViewImageTool));
        assert!(features.enabled(crate::features::Feature::WebSearchRequest));
    }

    #[tokio::test]
    async fn persist_approved_plan_writes_plan_markdown() -> anyhow::Result<()> {
        let temp = TempDir::new().expect("tmp dir");
        let cwd = temp.path();
        let out = PlanOutputEvent {
            title: "My Plan".to_string(),
            summary: "Do the thing.".to_string(),
            plan: UpdatePlanArgs {
                explanation: Some("Some explanation.".to_string()),
                plan: vec![PlanItemArg {
                    step: "Step one".to_string(),
                    status: StepStatus::Pending,
                }],
            },
        };

        persist_approved_plan_markdown(&out, cwd).await?;

        let path = project_internal_paths::approved_plan_markdown_path(cwd);
        let contents = tokio::fs::read_to_string(path).await?;
        assert!(contents.contains("# My Plan"));
        assert!(contents.contains("## Steps"));
        assert!(contents.contains("- [pending] Step one"));
        Ok(())
    }
}
