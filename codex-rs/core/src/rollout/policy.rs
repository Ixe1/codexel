use crate::protocol::EventMsg;
use crate::protocol::RolloutItem;
use codex_protocol::models::ResponseItem;

/// Whether a rollout `item` should be persisted in rollout files.
#[inline]
pub(crate) fn is_persisted_response_item(item: &RolloutItem) -> bool {
    match item {
        RolloutItem::ResponseItem(item) => should_persist_response_item(item),
        RolloutItem::EventMsg(ev) => should_persist_event_msg(ev),
        // Persist Codex executive markers so we can analyze flows (e.g., compaction, API turns).
        RolloutItem::Compacted(_) | RolloutItem::TurnContext(_) | RolloutItem::SessionMeta(_) => {
            true
        }
    }
}

/// Whether a `ResponseItem` should be persisted in rollout files.
#[inline]
pub(crate) fn should_persist_response_item(item: &ResponseItem) -> bool {
    match item {
        ResponseItem::Message { .. }
        | ResponseItem::Reasoning { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::GhostSnapshot { .. }
        | ResponseItem::Compaction { .. } => true,
        ResponseItem::Other => false,
    }
}

/// Whether an `EventMsg` should be persisted in rollout files.
#[inline]
pub(crate) fn should_persist_event_msg(ev: &EventMsg) -> bool {
    match ev {
        EventMsg::UserMessage(_)
        | EventMsg::AgentMessage(_)
        | EventMsg::AgentMessageDelta(_)
        | EventMsg::AgentReasoning(_)
        | EventMsg::AgentReasoningDelta(_)
        | EventMsg::AgentReasoningRawContent(_)
        | EventMsg::AgentReasoningRawContentDelta(_)
        | EventMsg::AgentReasoningSectionBreak(_)
        | EventMsg::TokenCount(_)
        | EventMsg::ContextCompacted(_)
        | EventMsg::EnteredReviewMode(_)
        | EventMsg::ExitedReviewMode(_)
        | EventMsg::EnteredPlanMode(_)
        | EventMsg::ExitedPlanMode(_)
        | EventMsg::UndoCompleted(_)
        | EventMsg::TurnAborted(_)
        | EventMsg::McpToolCallBegin(_)
        | EventMsg::McpToolCallEnd(_)
        | EventMsg::SubAgentToolCallBegin(_)
        | EventMsg::SubAgentToolCallActivity(_)
        | EventMsg::SubAgentToolCallTokens(_)
        | EventMsg::SubAgentToolCallEnd(_)
        | EventMsg::WebSearchBegin(_)
        | EventMsg::WebSearchEnd(_)
        | EventMsg::ExecCommandBegin(_)
        | EventMsg::TerminalInteraction(_)
        | EventMsg::ExecCommandOutputDelta(_)
        | EventMsg::ExecCommandEnd(_)
        | EventMsg::PatchApplyBegin(_)
        | EventMsg::PatchApplyEnd(_)
        | EventMsg::ViewImageToolCall(_) => true,
        EventMsg::Error(_)
        | EventMsg::Warning(_)
        | EventMsg::TaskStarted(_)
        | EventMsg::TaskComplete(_)
        | EventMsg::RawResponseItem(_)
        | EventMsg::SessionConfigured(_)
        | EventMsg::ExecApprovalRequest(_)
        | EventMsg::ElicitationRequest(_)
        | EventMsg::AskUserQuestionRequest(_)
        | EventMsg::PlanApprovalRequest(_)
        | EventMsg::ApplyPatchApprovalRequest(_)
        | EventMsg::BackgroundEvent(_)
        | EventMsg::StreamError(_)
        | EventMsg::TurnDiff(_)
        | EventMsg::GetHistoryEntryResponse(_)
        | EventMsg::UndoStarted(_)
        | EventMsg::McpListToolsResponse(_)
        | EventMsg::McpStartupUpdate(_)
        | EventMsg::McpStartupComplete(_)
        | EventMsg::ListCustomPromptsResponse(_)
        | EventMsg::ListSkillsResponse(_)
        | EventMsg::PlanUpdate(_)
        | EventMsg::ShutdownComplete
        | EventMsg::DeprecationNotice(_)
        | EventMsg::ItemStarted(_)
        | EventMsg::ItemCompleted(_)
        | EventMsg::AgentMessageContentDelta(_)
        | EventMsg::ReasoningContentDelta(_)
        | EventMsg::ReasoningRawContentDelta(_)
        | EventMsg::SkillsUpdateAvailable => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AgentMessageDeltaEvent;
    use crate::protocol::ExecCommandBeginEvent;
    use crate::protocol::ExecCommandOutputDeltaEvent;
    use crate::protocol::ExecCommandSource;
    use crate::protocol::ExecOutputStream;
    use crate::protocol::McpInvocation;
    use crate::protocol::McpToolCallBeginEvent;
    use crate::protocol::PatchApplyBeginEvent;
    use crate::protocol::SubAgentInvocation;
    use crate::protocol::SubAgentToolCallBeginEvent;
    use crate::protocol::TerminalInteractionEvent;
    use crate::protocol::ViewImageToolCallEvent;
    use crate::protocol::WebSearchEndEvent;
    use codex_protocol::protocol::FileChange;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn persists_streaming_deltas_and_tool_lifecycle_events() {
        assert!(should_persist_event_msg(&EventMsg::AgentMessageDelta(
            AgentMessageDeltaEvent {
                delta: "hello".to_string(),
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::ExecCommandBegin(
            ExecCommandBeginEvent {
                call_id: "call-1".to_string(),
                process_id: None,
                turn_id: "turn-1".to_string(),
                command: vec!["echo".to_string(), "hi".to_string()],
                cwd: PathBuf::from("/tmp"),
                parsed_cmd: Vec::new(),
                source: ExecCommandSource::Agent,
                interaction_input: None,
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::ExecCommandOutputDelta(
            ExecCommandOutputDeltaEvent {
                call_id: "call-1".to_string(),
                stream: ExecOutputStream::Stdout,
                chunk: b"hi".to_vec(),
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::TerminalInteraction(
            TerminalInteractionEvent {
                call_id: "call-1".to_string(),
                process_id: "pid-1".to_string(),
                stdin: "ls\n".to_string(),
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::McpToolCallBegin(
            McpToolCallBeginEvent {
                call_id: "call-2".to_string(),
                invocation: McpInvocation {
                    server: "srv".to_string(),
                    tool: "tool".to_string(),
                    arguments: None,
                },
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::SubAgentToolCallBegin(
            SubAgentToolCallBeginEvent {
                call_id: "call-3".to_string(),
                invocation: SubAgentInvocation {
                    description: "desc".to_string(),
                    label: "label".to_string(),
                    prompt: "prompt".to_string(),
                    model: None,
                },
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::WebSearchEnd(
            WebSearchEndEvent {
                call_id: "call-4".to_string(),
                query: "query".to_string(),
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::PatchApplyBegin(
            PatchApplyBeginEvent {
                call_id: "call-5".to_string(),
                turn_id: "turn-1".to_string(),
                auto_approved: true,
                changes: HashMap::<PathBuf, FileChange>::new(),
            }
        )));

        assert!(should_persist_event_msg(&EventMsg::ViewImageToolCall(
            ViewImageToolCallEvent {
                call_id: "call-6".to_string(),
                path: PathBuf::from("image.png"),
            }
        )));
    }
}
