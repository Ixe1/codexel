use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::SubAgentInvocation;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::SubAgentToolCallActivityEvent;
use codex_protocol::protocol::SubAgentToolCallBeginEvent;
use codex_protocol::protocol::SubAgentToolCallEndEvent;
use codex_protocol::protocol::SubAgentToolCallOutcome;
use codex_protocol::protocol::SubAgentToolCallTokensEvent;
use codex_protocol::protocol::TokenCountEvent;
use codex_protocol::user_input::UserInput;
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::codex_delegate::run_codex_conversation_one_shot;
use crate::config::Config;

pub(crate) async fn run_subagent_tool_call(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: String,
    invocation: SubAgentInvocation,
    cfg: Config,
    input: Vec<UserInput>,
    source: SubAgentSource,
) -> Result<String, String> {
    session
        .send_event(
            turn.as_ref(),
            EventMsg::SubAgentToolCallBegin(SubAgentToolCallBeginEvent {
                call_id: call_id.clone(),
                invocation: invocation.clone(),
            }),
        )
        .await;
    session
        .send_event(
            turn.as_ref(),
            EventMsg::SubAgentToolCallActivity(SubAgentToolCallActivityEvent {
                call_id: call_id.clone(),
                activity: "starting".to_string(),
            }),
        )
        .await;

    let started_at = Instant::now();
    let cancel = session
        .turn_cancellation_token(&turn.sub_id)
        .await
        .map_or_else(CancellationToken::new, |token| token.child_token());
    let _cancel_guard = CancelOnDrop::new(cancel.clone());

    let io = match run_codex_conversation_one_shot(
        cfg,
        Arc::clone(&session.services.auth_manager),
        Arc::clone(&session.services.models_manager),
        input,
        Arc::clone(&session),
        Arc::clone(&turn),
        cancel,
        None,
        source,
    )
    .await
    {
        Ok(io) => io,
        Err(err) => {
            let message = format!("failed to start subagent: {err}");
            session
                .send_event(
                    turn.as_ref(),
                    EventMsg::SubAgentToolCallEnd(SubAgentToolCallEndEvent {
                        call_id,
                        invocation,
                        duration: started_at.elapsed(),
                        tokens: None,
                        outcome: Some(SubAgentToolCallOutcome::Completed),
                        result: Err(message.clone()),
                    }),
                )
                .await;
            return Err(message);
        }
    };

    let mut last_agent_message: Option<String> = None;
    let mut last_activity: Option<String> = None;
    let mut tokens: i64 = 0;
    let mut last_reported_tokens: Option<i64> = None;
    let mut last_reported_at = Instant::now();
    let mut aborted = false;

    while let Ok(Event { msg, .. }) = io.rx_event.recv().await {
        if let Some(activity) = activity_for_event(&msg)
            && last_activity.as_deref() != Some(activity.as_str())
        {
            last_activity = Some(activity.clone());
            session
                .send_event(
                    turn.as_ref(),
                    EventMsg::SubAgentToolCallActivity(SubAgentToolCallActivityEvent {
                        call_id: call_id.clone(),
                        activity,
                    }),
                )
                .await;
        }

        match msg {
            EventMsg::TaskComplete(ev) => {
                last_agent_message = ev.last_agent_message;
                break;
            }
            EventMsg::TurnAborted(_) => {
                aborted = true;
                break;
            }
            EventMsg::TokenCount(TokenCountEvent {
                info: Some(info), ..
            }) => {
                tokens = tokens.saturating_add(info.last_token_usage.total_tokens.max(0));
                let now = Instant::now();
                let should_report =
                    match (last_reported_tokens, last_reported_at.elapsed().as_secs()) {
                        (Some(prev), secs) => tokens > prev && (tokens - prev >= 250 || secs >= 2),
                        (None, _) => tokens > 0,
                    };
                if should_report {
                    session
                        .send_event(
                            turn.as_ref(),
                            EventMsg::SubAgentToolCallTokens(SubAgentToolCallTokensEvent {
                                call_id: call_id.clone(),
                                tokens,
                            }),
                        )
                        .await;
                    last_reported_tokens = Some(tokens);
                    last_reported_at = now;
                }
            }
            _ => {}
        }
    }

    let response = last_agent_message.unwrap_or_default().trim().to_string();
    let tokens = if tokens > 0 { Some(tokens) } else { None };

    if aborted {
        let message = "cancelled".to_string();
        session
            .send_event(
                turn.as_ref(),
                EventMsg::SubAgentToolCallEnd(SubAgentToolCallEndEvent {
                    call_id,
                    invocation,
                    duration: started_at.elapsed(),
                    tokens: None,
                    outcome: Some(SubAgentToolCallOutcome::Cancelled),
                    result: Err(message.clone()),
                }),
            )
            .await;
        return Err(message);
    }

    session
        .send_event(
            turn.as_ref(),
            EventMsg::SubAgentToolCallEnd(SubAgentToolCallEndEvent {
                call_id,
                invocation,
                duration: started_at.elapsed(),
                tokens,
                outcome: Some(SubAgentToolCallOutcome::Completed),
                result: Ok(response.clone()),
            }),
        )
        .await;

    Ok(response)
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

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
}
