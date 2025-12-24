use async_trait::async_trait;
use codex_protocol::plan_mode::PlanOutputEvent;
use codex_protocol::plan_tool::UpdatePlanArgs;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentInvocation;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::user_input::UserInput;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::task::JoinSet;

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
            call_id,
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
            let variant_call_id = format!("{call_id}:plan_variant:{idx}");
            let base_config = turn.client.config().as_ref().clone();
            let goal = goal.to_string();
            let session = Arc::clone(&session);
            let turn = Arc::clone(&turn);
            join_set.spawn(async move {
                let invocation = SubAgentInvocation {
                    description: format!(
                        "Plan variant {idx}/{TOTAL}: {}",
                        variant_title(idx, TOTAL)
                    ),
                    label: format!("plan_variant_{idx}"),
                    prompt: format!("Goal: {goal}\n\nReturn plan variant #{idx}."),
                };
                let out = run_one_variant(PlanVariantRunArgs {
                    call_id: variant_call_id,
                    invocation,
                    base_config,
                    goal,
                    idx,
                    total: TOTAL,
                    label,
                    parent_session: Arc::clone(&session),
                    parent_ctx: Arc::clone(&turn),
                })
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

async fn run_one_variant(args: PlanVariantRunArgs) -> PlanOutputEvent {
    let PlanVariantRunArgs {
        call_id,
        invocation,
        base_config,
        goal,
        idx,
        total,
        label,
        parent_session,
        parent_ctx,
    } = args;

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

    let response = match crate::tools::subagent_runner::run_subagent_tool_call(
        parent_session,
        Arc::clone(&parent_ctx),
        call_id,
        invocation,
        cfg,
        input,
        SubAgentSource::Other(label),
    )
    .await
    {
        Ok(response) => response,
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

    parse_plan_output_event(idx, total, response.as_str())
}

struct PlanVariantRunArgs {
    call_id: String,
    invocation: SubAgentInvocation,
    base_config: Config,
    goal: String,
    idx: usize,
    total: usize,
    label: String,
    parent_session: Arc<crate::codex::Session>,
    parent_ctx: Arc<crate::codex::TurnContext>,
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
