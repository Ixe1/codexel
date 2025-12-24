use crate::protocol::v2::CommandAction;
use crate::protocol::v2::CommandExecutionStatus;
use crate::protocol::v2::FileUpdateChange;
use crate::protocol::v2::McpToolCallError;
use crate::protocol::v2::McpToolCallResult;
use crate::protocol::v2::McpToolCallStatus;
use crate::protocol::v2::PatchApplyStatus;
use crate::protocol::v2::PatchChangeKind;
use crate::protocol::v2::ThreadItem;
use crate::protocol::v2::Turn;
use crate::protocol::v2::TurnError;
use crate::protocol::v2::TurnStatus;
use crate::protocol::v2::UserInput;
use codex_protocol::protocol::AgentMessageDeltaEvent;
use codex_protocol::protocol::AgentReasoningDeltaEvent;
use codex_protocol::protocol::AgentReasoningEvent;
use codex_protocol::protocol::AgentReasoningRawContentDeltaEvent;
use codex_protocol::protocol::AgentReasoningRawContentEvent;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ExecCommandBeginEvent;
use codex_protocol::protocol::ExecCommandEndEvent;
use codex_protocol::protocol::ExecCommandOutputDeltaEvent;
use codex_protocol::protocol::FileChange;
use codex_protocol::protocol::McpToolCallBeginEvent;
use codex_protocol::protocol::McpToolCallEndEvent;
use codex_protocol::protocol::PatchApplyBeginEvent;
use codex_protocol::protocol::PatchApplyEndEvent;
use codex_protocol::protocol::TurnAbortedEvent;
use codex_protocol::protocol::UserMessageEvent;
use codex_protocol::protocol::ViewImageToolCallEvent;
use codex_protocol::protocol::WebSearchBeginEvent;
use codex_protocol::protocol::WebSearchEndEvent;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::time::Duration;

/// Convert persisted [`EventMsg`] entries into a sequence of [`Turn`] values.
///
/// The purpose of this is to convert the EventMsgs persisted in a rollout file
/// into a sequence of Turns and ThreadItems, which allows the client to render
/// the historical messages when resuming a thread.
pub fn build_turns_from_event_msgs(events: &[EventMsg]) -> Vec<Turn> {
    let mut builder = ThreadHistoryBuilder::new();
    for event in events {
        builder.handle_event(event);
    }
    builder.finish()
}

struct ThreadHistoryBuilder {
    turns: Vec<Turn>,
    current_turn: Option<PendingTurn>,
    next_turn_index: i64,
    next_item_index: i64,
    streaming_agent_message: bool,
    streaming_reasoning_summary: bool,
    streaming_reasoning_raw: bool,
    exec_items: HashMap<String, usize>,
    exec_output: HashMap<String, String>,
    patch_items: HashMap<String, usize>,
    mcp_items: HashMap<String, usize>,
}

impl ThreadHistoryBuilder {
    fn new() -> Self {
        Self {
            turns: Vec::new(),
            current_turn: None,
            next_turn_index: 1,
            next_item_index: 1,
            streaming_agent_message: false,
            streaming_reasoning_summary: false,
            streaming_reasoning_raw: false,
            exec_items: HashMap::new(),
            exec_output: HashMap::new(),
            patch_items: HashMap::new(),
            mcp_items: HashMap::new(),
        }
    }

    fn finish(mut self) -> Vec<Turn> {
        self.finish_current_turn();
        self.turns
    }

    /// This function should handle all EventMsg variants that can be persisted in a rollout file.
    /// See `should_persist_event_msg` in `codex-rs/core/rollout/policy.rs`.
    fn handle_event(&mut self, event: &EventMsg) {
        match event {
            EventMsg::UserMessage(payload) => self.handle_user_message(payload),
            EventMsg::AgentMessage(payload) => self.handle_agent_message(payload.message.clone()),
            EventMsg::AgentMessageDelta(payload) => self.handle_agent_message_delta(payload),
            EventMsg::AgentReasoning(payload) => self.handle_agent_reasoning(payload),
            EventMsg::AgentReasoningDelta(payload) => self.handle_agent_reasoning_delta(payload),
            EventMsg::AgentReasoningRawContent(payload) => {
                self.handle_agent_reasoning_raw_content(payload)
            }
            EventMsg::AgentReasoningRawContentDelta(payload) => {
                self.handle_agent_reasoning_raw_content_delta(payload)
            }
            EventMsg::ExecCommandBegin(payload) => self.handle_exec_command_begin(payload),
            EventMsg::ExecCommandOutputDelta(payload) => {
                self.handle_exec_command_output_delta(payload)
            }
            EventMsg::ExecCommandEnd(payload) => self.handle_exec_command_end(payload),
            EventMsg::PatchApplyBegin(payload) => self.handle_patch_apply_begin(payload),
            EventMsg::PatchApplyEnd(payload) => self.handle_patch_apply_end(payload),
            EventMsg::McpToolCallBegin(payload) => self.handle_mcp_tool_call_begin(payload),
            EventMsg::McpToolCallEnd(payload) => self.handle_mcp_tool_call_end(payload),
            EventMsg::WebSearchBegin(payload) => self.handle_web_search_begin(payload),
            EventMsg::WebSearchEnd(payload) => self.handle_web_search_end(payload),
            EventMsg::ViewImageToolCall(payload) => self.handle_view_image_tool_call(payload),
            EventMsg::TokenCount(_) => {}
            EventMsg::EnteredReviewMode(_) => {}
            EventMsg::ExitedReviewMode(_) => {}
            EventMsg::UndoCompleted(_) => {}
            EventMsg::TurnAborted(payload) => self.handle_turn_aborted(payload),
            _ => {}
        }
    }

    fn handle_user_message(&mut self, payload: &UserMessageEvent) {
        self.finish_current_turn();
        let mut turn = self.new_turn();
        let id = self.next_item_id();
        let content = self.build_user_inputs(payload);
        turn.items.push(ThreadItem::UserMessage { id, content });
        self.current_turn = Some(turn);
    }

    fn handle_agent_message(&mut self, text: String) {
        if text.is_empty() {
            return;
        }

        if self.streaming_agent_message
            && let Some(ThreadItem::AgentMessage { text: existing, .. }) =
                self.ensure_turn().items.last_mut()
        {
            *existing = text;
            self.streaming_agent_message = false;
            return;
        }

        self.streaming_agent_message = false;
        let id = self.next_item_id();
        self.ensure_turn()
            .items
            .push(ThreadItem::AgentMessage { id, text });
    }

    fn handle_agent_message_delta(&mut self, payload: &AgentMessageDeltaEvent) {
        if payload.delta.is_empty() {
            return;
        }

        if self.streaming_agent_message
            && let Some(ThreadItem::AgentMessage { text, .. }) = self.ensure_turn().items.last_mut()
        {
            text.push_str(&payload.delta);
            return;
        }

        let id = self.next_item_id();
        self.ensure_turn().items.push(ThreadItem::AgentMessage {
            id,
            text: payload.delta.clone(),
        });
        self.streaming_agent_message = true;
    }

    fn handle_agent_reasoning(&mut self, payload: &AgentReasoningEvent) {
        if payload.text.is_empty() {
            self.streaming_reasoning_summary = false;
            return;
        }

        let was_streaming = self.streaming_reasoning_summary;
        // If the last item is a reasoning item, add the new text to the summary.
        if let Some(ThreadItem::Reasoning { summary, .. }) = self.ensure_turn().items.last_mut() {
            if was_streaming && !summary.is_empty() {
                if let Some(last) = summary.last_mut() {
                    *last = payload.text.clone();
                }
            } else {
                summary.push(payload.text.clone());
            }
            self.streaming_reasoning_summary = false;
            return;
        }

        // Otherwise, create a new reasoning item.
        self.streaming_reasoning_summary = false;
        let id = self.next_item_id();
        self.ensure_turn().items.push(ThreadItem::Reasoning {
            id,
            summary: vec![payload.text.clone()],
            content: Vec::new(),
        });
    }

    fn handle_agent_reasoning_delta(&mut self, payload: &AgentReasoningDeltaEvent) {
        if payload.delta.is_empty() {
            return;
        }

        if self.streaming_reasoning_summary
            && let Some(ThreadItem::Reasoning { summary, .. }) = self.ensure_turn().items.last_mut()
        {
            if let Some(last) = summary.last_mut() {
                last.push_str(&payload.delta);
            } else {
                summary.push(payload.delta.clone());
            }
            return;
        }

        self.streaming_reasoning_summary = true;
        let id = self.next_item_id();
        self.ensure_turn().items.push(ThreadItem::Reasoning {
            id,
            summary: vec![payload.delta.clone()],
            content: Vec::new(),
        });
    }

    fn handle_agent_reasoning_raw_content(&mut self, payload: &AgentReasoningRawContentEvent) {
        if payload.text.is_empty() {
            self.streaming_reasoning_raw = false;
            return;
        }

        let was_streaming = self.streaming_reasoning_raw;
        // If the last item is a reasoning item, add the new text to the content.
        if let Some(ThreadItem::Reasoning { content, .. }) = self.ensure_turn().items.last_mut() {
            if was_streaming && !content.is_empty() {
                if let Some(last) = content.last_mut() {
                    *last = payload.text.clone();
                }
            } else {
                content.push(payload.text.clone());
            }
            self.streaming_reasoning_raw = false;
            return;
        }

        // Otherwise, create a new reasoning item.
        self.streaming_reasoning_raw = false;
        let id = self.next_item_id();
        self.ensure_turn().items.push(ThreadItem::Reasoning {
            id,
            summary: Vec::new(),
            content: vec![payload.text.clone()],
        });
    }

    fn handle_agent_reasoning_raw_content_delta(
        &mut self,
        payload: &AgentReasoningRawContentDeltaEvent,
    ) {
        if payload.delta.is_empty() {
            return;
        }

        if self.streaming_reasoning_raw
            && let Some(ThreadItem::Reasoning { content, .. }) = self.ensure_turn().items.last_mut()
        {
            if let Some(last) = content.last_mut() {
                last.push_str(&payload.delta);
            } else {
                content.push(payload.delta.clone());
            }
            return;
        }

        self.streaming_reasoning_raw = true;
        let id = self.next_item_id();
        self.ensure_turn().items.push(ThreadItem::Reasoning {
            id,
            summary: Vec::new(),
            content: vec![payload.delta.clone()],
        });
    }

    fn handle_exec_command_begin(&mut self, payload: &ExecCommandBeginEvent) {
        let id = payload.call_id.clone();
        let command = payload.command.join(" ");
        let command_actions = payload
            .parsed_cmd
            .iter()
            .cloned()
            .map(CommandAction::from)
            .collect();

        let item = ThreadItem::CommandExecution {
            id: id.clone(),
            command,
            cwd: payload.cwd.clone(),
            process_id: payload.process_id.clone(),
            status: CommandExecutionStatus::InProgress,
            command_actions,
            aggregated_output: None,
            exit_code: None,
            duration_ms: None,
        };

        let turn = self.ensure_turn();
        let index = turn.items.len();
        turn.items.push(item);
        self.exec_items.insert(id.clone(), index);
        self.exec_output.insert(id, String::new());
    }

    fn handle_exec_command_output_delta(&mut self, payload: &ExecCommandOutputDeltaEvent) {
        let Some(index) = self.exec_items.get(&payload.call_id).copied() else {
            return;
        };

        let text = String::from_utf8_lossy(&payload.chunk).to_string();
        let output = {
            let output = self.exec_output.entry(payload.call_id.clone()).or_default();
            output.push_str(&text);
            output.clone()
        };

        let Some(ThreadItem::CommandExecution {
            aggregated_output, ..
        }) = self.ensure_turn().items.get_mut(index)
        else {
            return;
        };

        *aggregated_output = Some(output);
    }

    fn handle_exec_command_end(&mut self, payload: &ExecCommandEndEvent) {
        let output = self
            .exec_output
            .remove(&payload.call_id)
            .unwrap_or_default();
        let best_output = if !payload.aggregated_output.is_empty() {
            payload.aggregated_output.clone()
        } else if !output.is_empty() {
            output
        } else if !payload.stdout.is_empty() || !payload.stderr.is_empty() {
            format!(
                "{stdout}{stderr}",
                stdout = payload.stdout,
                stderr = payload.stderr
            )
        } else {
            String::new()
        };

        let duration_ms = duration_to_ms(payload.duration);
        let status = if payload.exit_code == 0 {
            CommandExecutionStatus::Completed
        } else {
            CommandExecutionStatus::Failed
        };

        let Some(index) = self.exec_items.get(&payload.call_id).copied() else {
            let item = ThreadItem::CommandExecution {
                id: payload.call_id.clone(),
                command: payload.command.join(" "),
                cwd: payload.cwd.clone(),
                process_id: payload.process_id.clone(),
                status,
                command_actions: payload
                    .parsed_cmd
                    .iter()
                    .cloned()
                    .map(CommandAction::from)
                    .collect(),
                aggregated_output: Some(best_output),
                exit_code: Some(payload.exit_code),
                duration_ms,
            };
            self.ensure_turn().items.push(item);
            return;
        };

        let Some(ThreadItem::CommandExecution {
            status: existing_status,
            aggregated_output,
            exit_code,
            duration_ms: existing_duration_ms,
            ..
        }) = self.ensure_turn().items.get_mut(index)
        else {
            return;
        };

        *existing_status = status;
        *aggregated_output = Some(best_output);
        *exit_code = Some(payload.exit_code);
        *existing_duration_ms = duration_ms;
    }

    fn handle_patch_apply_begin(&mut self, payload: &PatchApplyBeginEvent) {
        let id = payload.call_id.clone();
        let changes = build_file_updates(&payload.changes);
        let item = ThreadItem::FileChange {
            id: id.clone(),
            changes,
            status: PatchApplyStatus::InProgress,
        };

        let turn = self.ensure_turn();
        let index = turn.items.len();
        turn.items.push(item);
        self.patch_items.insert(id, index);
    }

    fn handle_patch_apply_end(&mut self, payload: &PatchApplyEndEvent) {
        let status = if payload.success {
            PatchApplyStatus::Completed
        } else {
            PatchApplyStatus::Failed
        };
        let changes = build_file_updates(&payload.changes);

        let Some(index) = self.patch_items.get(&payload.call_id).copied() else {
            self.ensure_turn().items.push(ThreadItem::FileChange {
                id: payload.call_id.clone(),
                changes,
                status,
            });
            return;
        };

        let Some(ThreadItem::FileChange {
            status: existing_status,
            changes: existing_changes,
            ..
        }) = self.ensure_turn().items.get_mut(index)
        else {
            return;
        };

        *existing_status = status;
        *existing_changes = changes;
    }

    fn handle_mcp_tool_call_begin(&mut self, payload: &McpToolCallBeginEvent) {
        let id = payload.call_id.clone();
        let invocation = &payload.invocation;
        let arguments = invocation.arguments.clone().unwrap_or(JsonValue::Null);

        let item = ThreadItem::McpToolCall {
            id: id.clone(),
            server: invocation.server.clone(),
            tool: invocation.tool.clone(),
            status: McpToolCallStatus::InProgress,
            arguments,
            result: None,
            error: None,
            duration_ms: None,
        };

        let turn = self.ensure_turn();
        let index = turn.items.len();
        turn.items.push(item);
        self.mcp_items.insert(id, index);
    }

    fn handle_mcp_tool_call_end(&mut self, payload: &McpToolCallEndEvent) {
        let duration_ms = duration_to_ms(payload.duration);
        let invocation = &payload.invocation;
        let arguments = invocation.arguments.clone().unwrap_or(JsonValue::Null);

        let (status, result, error) = match &payload.result {
            Ok(result) => {
                let is_error = result.is_error.unwrap_or(false);
                (
                    if is_error {
                        McpToolCallStatus::Failed
                    } else {
                        McpToolCallStatus::Completed
                    },
                    Some(McpToolCallResult {
                        content: result.content.clone(),
                        structured_content: result.structured_content.clone(),
                    }),
                    None,
                )
            }
            Err(message) => (
                McpToolCallStatus::Failed,
                None,
                Some(McpToolCallError {
                    message: message.clone(),
                }),
            ),
        };

        let Some(index) = self.mcp_items.get(&payload.call_id).copied() else {
            self.ensure_turn().items.push(ThreadItem::McpToolCall {
                id: payload.call_id.clone(),
                server: invocation.server.clone(),
                tool: invocation.tool.clone(),
                status,
                arguments,
                result,
                error,
                duration_ms,
            });
            return;
        };

        let Some(ThreadItem::McpToolCall {
            status: existing_status,
            arguments: existing_arguments,
            result: existing_result,
            error: existing_error,
            duration_ms: existing_duration_ms,
            ..
        }) = self.ensure_turn().items.get_mut(index)
        else {
            return;
        };

        *existing_status = status;
        *existing_arguments = arguments;
        *existing_result = result;
        *existing_error = error;
        *existing_duration_ms = duration_ms;
    }

    fn handle_web_search_begin(&mut self, _payload: &WebSearchBeginEvent) {}

    fn handle_web_search_end(&mut self, payload: &WebSearchEndEvent) {
        self.ensure_turn().items.push(ThreadItem::WebSearch {
            id: payload.call_id.clone(),
            query: payload.query.clone(),
        });
    }

    fn handle_view_image_tool_call(&mut self, payload: &ViewImageToolCallEvent) {
        self.ensure_turn().items.push(ThreadItem::ImageView {
            id: payload.call_id.clone(),
            path: payload.path.to_string_lossy().to_string(),
        });
    }

    fn handle_turn_aborted(&mut self, _payload: &TurnAbortedEvent) {
        let Some(turn) = self.current_turn.as_mut() else {
            return;
        };
        turn.status = TurnStatus::Interrupted;
    }

    fn finish_current_turn(&mut self) {
        if let Some(turn) = self.current_turn.take() {
            if turn.items.is_empty() {
                return;
            }
            self.turns.push(turn.into());
        }
        self.exec_items.clear();
        self.exec_output.clear();
        self.patch_items.clear();
        self.mcp_items.clear();
        self.streaming_agent_message = false;
        self.streaming_reasoning_summary = false;
        self.streaming_reasoning_raw = false;
    }

    fn new_turn(&mut self) -> PendingTurn {
        PendingTurn {
            id: self.next_turn_id(),
            items: Vec::new(),
            error: None,
            status: TurnStatus::Completed,
        }
    }

    fn ensure_turn(&mut self) -> &mut PendingTurn {
        if self.current_turn.is_none() {
            let turn = self.new_turn();
            return self.current_turn.insert(turn);
        }

        if let Some(turn) = self.current_turn.as_mut() {
            return turn;
        }

        unreachable!("current turn must exist after initialization");
    }

    fn next_turn_id(&mut self) -> String {
        let id = format!("turn-{}", self.next_turn_index);
        self.next_turn_index += 1;
        id
    }

    fn next_item_id(&mut self) -> String {
        let id = format!("item-{}", self.next_item_index);
        self.next_item_index += 1;
        id
    }

    fn build_user_inputs(&self, payload: &UserMessageEvent) -> Vec<UserInput> {
        let mut content = Vec::new();
        if !payload.message.trim().is_empty() {
            content.push(UserInput::Text {
                text: payload.message.clone(),
            });
        }
        if let Some(images) = &payload.images {
            for image in images {
                content.push(UserInput::Image { url: image.clone() });
            }
        }
        content
    }
}

struct PendingTurn {
    id: String,
    items: Vec<ThreadItem>,
    error: Option<TurnError>,
    status: TurnStatus,
}

impl From<PendingTurn> for Turn {
    fn from(value: PendingTurn) -> Self {
        Self {
            id: value.id,
            items: value.items,
            error: value.error,
            status: value.status,
        }
    }
}

fn duration_to_ms(duration: Duration) -> Option<i64> {
    i64::try_from(duration.as_millis()).ok()
}

fn build_file_updates(changes: &HashMap<std::path::PathBuf, FileChange>) -> Vec<FileUpdateChange> {
    let mut items: Vec<_> = changes.iter().collect();
    items.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

    items
        .into_iter()
        .map(|(path, change)| {
            let (kind, diff) = match change {
                FileChange::Add { content } => (PatchChangeKind::Add, content.clone()),
                FileChange::Delete { content } => (PatchChangeKind::Delete, content.clone()),
                FileChange::Update {
                    unified_diff,
                    move_path,
                } => (
                    PatchChangeKind::Update {
                        move_path: move_path.clone(),
                    },
                    unified_diff.clone(),
                ),
            };
            FileUpdateChange {
                path: path.to_string_lossy().to_string(),
                kind,
                diff,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::protocol::AgentMessageDeltaEvent;
    use codex_protocol::protocol::AgentMessageEvent;
    
    use codex_protocol::protocol::AgentReasoningEvent;
    
    use codex_protocol::protocol::AgentReasoningRawContentEvent;
    use codex_protocol::protocol::ExecCommandBeginEvent;
    
    use codex_protocol::protocol::ExecCommandOutputDeltaEvent;
    use codex_protocol::protocol::ExecCommandSource;
    use codex_protocol::protocol::ExecOutputStream;
    use codex_protocol::protocol::McpInvocation;
    use codex_protocol::protocol::McpToolCallBeginEvent;
    use codex_protocol::protocol::McpToolCallEndEvent;
    use codex_protocol::protocol::PatchApplyBeginEvent;
    use codex_protocol::protocol::PatchApplyEndEvent;
    use codex_protocol::protocol::TurnAbortReason;
    use codex_protocol::protocol::TurnAbortedEvent;
    use codex_protocol::protocol::UserMessageEvent;
    use codex_protocol::protocol::ViewImageToolCallEvent;
    use codex_protocol::protocol::WebSearchEndEvent;
    use mcp_types::CallToolResult;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn builds_multiple_turns_with_reasoning_items() {
        let events = vec![
            EventMsg::UserMessage(UserMessageEvent {
                message: "First turn".into(),
                images: Some(vec!["https://example.com/one.png".into()]),
            }),
            EventMsg::AgentMessage(AgentMessageEvent {
                message: "Hi there".into(),
            }),
            EventMsg::AgentReasoning(AgentReasoningEvent {
                text: "thinking".into(),
            }),
            EventMsg::AgentReasoningRawContent(AgentReasoningRawContentEvent {
                text: "full reasoning".into(),
            }),
            EventMsg::UserMessage(UserMessageEvent {
                message: "Second turn".into(),
                images: None,
            }),
            EventMsg::AgentMessage(AgentMessageEvent {
                message: "Reply two".into(),
            }),
        ];

        let turns = build_turns_from_event_msgs(&events);
        assert_eq!(turns.len(), 2);

        let first = &turns[0];
        assert_eq!(first.id, "turn-1");
        assert_eq!(first.status, TurnStatus::Completed);
        assert_eq!(first.items.len(), 3);
        assert_eq!(
            first.items[0],
            ThreadItem::UserMessage {
                id: "item-1".into(),
                content: vec![
                    UserInput::Text {
                        text: "First turn".into(),
                    },
                    UserInput::Image {
                        url: "https://example.com/one.png".into(),
                    }
                ],
            }
        );
        assert_eq!(
            first.items[1],
            ThreadItem::AgentMessage {
                id: "item-2".into(),
                text: "Hi there".into(),
            }
        );
        assert_eq!(
            first.items[2],
            ThreadItem::Reasoning {
                id: "item-3".into(),
                summary: vec!["thinking".into()],
                content: vec!["full reasoning".into()],
            }
        );

        let second = &turns[1];
        assert_eq!(second.id, "turn-2");
        assert_eq!(second.items.len(), 2);
        assert_eq!(
            second.items[0],
            ThreadItem::UserMessage {
                id: "item-4".into(),
                content: vec![UserInput::Text {
                    text: "Second turn".into()
                }],
            }
        );
        assert_eq!(
            second.items[1],
            ThreadItem::AgentMessage {
                id: "item-5".into(),
                text: "Reply two".into(),
            }
        );
    }

    #[test]
    fn splits_reasoning_when_interleaved() {
        let events = vec![
            EventMsg::UserMessage(UserMessageEvent {
                message: "Turn start".into(),
                images: None,
            }),
            EventMsg::AgentReasoning(AgentReasoningEvent {
                text: "first summary".into(),
            }),
            EventMsg::AgentReasoningRawContent(AgentReasoningRawContentEvent {
                text: "first content".into(),
            }),
            EventMsg::AgentMessage(AgentMessageEvent {
                message: "interlude".into(),
            }),
            EventMsg::AgentReasoning(AgentReasoningEvent {
                text: "second summary".into(),
            }),
        ];

        let turns = build_turns_from_event_msgs(&events);
        assert_eq!(turns.len(), 1);
        let turn = &turns[0];
        assert_eq!(turn.items.len(), 4);

        assert_eq!(
            turn.items[1],
            ThreadItem::Reasoning {
                id: "item-2".into(),
                summary: vec!["first summary".into()],
                content: vec!["first content".into()],
            }
        );
        assert_eq!(
            turn.items[3],
            ThreadItem::Reasoning {
                id: "item-4".into(),
                summary: vec!["second summary".into()],
                content: Vec::new(),
            }
        );
    }

    #[test]
    fn marks_turn_as_interrupted_when_aborted() {
        let events = vec![
            EventMsg::UserMessage(UserMessageEvent {
                message: "Please do the thing".into(),
                images: None,
            }),
            EventMsg::AgentMessage(AgentMessageEvent {
                message: "Working...".into(),
            }),
            EventMsg::TurnAborted(TurnAbortedEvent {
                reason: TurnAbortReason::Replaced,
            }),
            EventMsg::UserMessage(UserMessageEvent {
                message: "Let's try again".into(),
                images: None,
            }),
            EventMsg::AgentMessage(AgentMessageEvent {
                message: "Second attempt complete.".into(),
            }),
        ];

        let turns = build_turns_from_event_msgs(&events);
        assert_eq!(turns.len(), 2);

        let first_turn = &turns[0];
        assert_eq!(first_turn.status, TurnStatus::Interrupted);
        assert_eq!(first_turn.items.len(), 2);
        assert_eq!(
            first_turn.items[0],
            ThreadItem::UserMessage {
                id: "item-1".into(),
                content: vec![UserInput::Text {
                    text: "Please do the thing".into()
                }],
            }
        );
        assert_eq!(
            first_turn.items[1],
            ThreadItem::AgentMessage {
                id: "item-2".into(),
                text: "Working...".into(),
            }
        );

        let second_turn = &turns[1];
        assert_eq!(second_turn.status, TurnStatus::Completed);
        assert_eq!(second_turn.items.len(), 2);
        assert_eq!(
            second_turn.items[0],
            ThreadItem::UserMessage {
                id: "item-3".into(),
                content: vec![UserInput::Text {
                    text: "Let's try again".into()
                }],
            }
        );
        assert_eq!(
            second_turn.items[1],
            ThreadItem::AgentMessage {
                id: "item-4".into(),
                text: "Second attempt complete.".into(),
            }
        );
    }

    #[test]
    fn replays_partial_assistant_message_and_in_progress_exec_output() {
        let events = vec![
            EventMsg::UserMessage(UserMessageEvent {
                message: "Do the thing".into(),
                images: None,
            }),
            EventMsg::AgentMessageDelta(AgentMessageDeltaEvent {
                delta: "Working".into(),
            }),
            EventMsg::ExecCommandBegin(ExecCommandBeginEvent {
                call_id: "call-1".into(),
                process_id: Some("pid-1".into()),
                turn_id: "turn-1".into(),
                command: vec!["echo".into(), "hi".into()],
                cwd: PathBuf::from("/tmp"),
                parsed_cmd: Vec::new(),
                source: ExecCommandSource::Agent,
                interaction_input: None,
            }),
            EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                call_id: "call-1".into(),
                stream: ExecOutputStream::Stdout,
                chunk: b"hi\n".to_vec(),
            }),
            EventMsg::TurnAborted(TurnAbortedEvent {
                reason: TurnAbortReason::Interrupted,
            }),
        ];

        let turns = build_turns_from_event_msgs(&events);
        assert_eq!(turns.len(), 1);
        let turn = &turns[0];
        assert_eq!(turn.status, TurnStatus::Interrupted);
        assert_eq!(turn.items.len(), 3);

        assert_eq!(
            turn.items[1],
            ThreadItem::AgentMessage {
                id: "item-2".into(),
                text: "Working".into(),
            }
        );
        assert_eq!(
            turn.items[2],
            ThreadItem::CommandExecution {
                id: "call-1".into(),
                command: "echo hi".into(),
                cwd: PathBuf::from("/tmp"),
                process_id: Some("pid-1".into()),
                status: CommandExecutionStatus::InProgress,
                command_actions: Vec::new(),
                aggregated_output: Some("hi\n".into()),
                exit_code: None,
                duration_ms: None,
            }
        );
    }

    #[test]
    fn updates_mcp_tool_call_status_on_end() {
        let events = vec![
            EventMsg::UserMessage(UserMessageEvent {
                message: "Search".into(),
                images: None,
            }),
            EventMsg::McpToolCallBegin(McpToolCallBeginEvent {
                call_id: "mcp-1".into(),
                invocation: McpInvocation {
                    server: "srv".into(),
                    tool: "tool".into(),
                    arguments: Some(json!({"q":"hi"})),
                },
            }),
            EventMsg::McpToolCallEnd(McpToolCallEndEvent {
                call_id: "mcp-1".into(),
                invocation: McpInvocation {
                    server: "srv".into(),
                    tool: "tool".into(),
                    arguments: Some(json!({"q":"hi"})),
                },
                duration: Duration::from_millis(12),
                result: Ok(CallToolResult {
                    content: Vec::new(),
                    structured_content: None,
                    is_error: Some(false),
                }),
            }),
        ];

        let turns = build_turns_from_event_msgs(&events);
        assert_eq!(turns.len(), 1);
        let turn = &turns[0];
        assert_eq!(turn.items.len(), 2);
        assert_eq!(
            turn.items[1],
            ThreadItem::McpToolCall {
                id: "mcp-1".into(),
                server: "srv".into(),
                tool: "tool".into(),
                status: McpToolCallStatus::Completed,
                arguments: json!({"q":"hi"}),
                result: Some(McpToolCallResult {
                    content: Vec::new(),
                    structured_content: None,
                }),
                error: None,
                duration_ms: Some(12),
            }
        );
    }

    #[test]
    fn replays_patch_and_web_search_and_image_view() {
        let mut changes = HashMap::new();
        changes.insert(
            PathBuf::from("file.txt"),
            codex_protocol::protocol::FileChange::Add {
                content: "hello".into(),
            },
        );

        let events = vec![
            EventMsg::UserMessage(UserMessageEvent {
                message: "Do work".into(),
                images: None,
            }),
            EventMsg::PatchApplyBegin(PatchApplyBeginEvent {
                call_id: "patch-1".into(),
                turn_id: "turn-1".into(),
                auto_approved: true,
                changes: changes.clone(),
            }),
            EventMsg::PatchApplyEnd(PatchApplyEndEvent {
                call_id: "patch-1".into(),
                turn_id: "turn-1".into(),
                stdout: "".into(),
                stderr: "".into(),
                success: true,
                changes,
            }),
            EventMsg::WebSearchEnd(WebSearchEndEvent {
                call_id: "ws-1".into(),
                query: "hello".into(),
            }),
            EventMsg::ViewImageToolCall(ViewImageToolCallEvent {
                call_id: "img-1".into(),
                path: PathBuf::from("image.png"),
            }),
        ];

        let turns = build_turns_from_event_msgs(&events);
        assert_eq!(turns.len(), 1);
        let turn = &turns[0];
        assert_eq!(turn.items.len(), 4);

        assert_eq!(
            turn.items[1],
            ThreadItem::FileChange {
                id: "patch-1".into(),
                changes: vec![FileUpdateChange {
                    path: "file.txt".into(),
                    kind: PatchChangeKind::Add,
                    diff: "hello".into(),
                }],
                status: PatchApplyStatus::Completed,
            }
        );
        assert_eq!(
            turn.items[2],
            ThreadItem::WebSearch {
                id: "ws-1".into(),
                query: "hello".into(),
            }
        );
        assert_eq!(
            turn.items[3],
            ThreadItem::ImageView {
                id: "img-1".into(),
                path: "image.png".into(),
            }
        );
    }
}
