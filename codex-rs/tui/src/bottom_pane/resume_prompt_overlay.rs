use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use ratatui::buffer::Buffer;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::style::Stylize as _;
use ratatui::text::Line;
use ratatui::widgets::Block;
use ratatui::widgets::Clear;
use ratatui::widgets::Widget as _;

use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use crate::render::Insets;
use crate::render::RectExt as _;
use crate::selection_list::selection_option_row;

use super::CancellationEvent;
use super::bottom_pane_view::BottomPaneView;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumeSelection {
    ResumePaused,
    Continue,
}

impl ResumeSelection {
    fn next(self) -> Self {
        match self {
            ResumeSelection::ResumePaused => ResumeSelection::Continue,
            ResumeSelection::Continue => ResumeSelection::ResumePaused,
        }
    }

    fn prev(self) -> Self {
        match self {
            ResumeSelection::ResumePaused => ResumeSelection::Continue,
            ResumeSelection::Continue => ResumeSelection::ResumePaused,
        }
    }
}

pub(crate) struct ResumePromptOverlay {
    app_event_tx: AppEventSender,
    highlighted: ResumeSelection,
    selection: Option<ResumeSelection>,
    had_partial_output: bool,
    had_in_progress_tools: bool,
}

impl ResumePromptOverlay {
    pub(crate) fn new(
        app_event_tx: AppEventSender,
        had_partial_output: bool,
        had_in_progress_tools: bool,
    ) -> Self {
        Self {
            app_event_tx,
            highlighted: ResumeSelection::ResumePaused,
            selection: None,
            had_partial_output,
            had_in_progress_tools,
        }
    }

    fn select(&mut self, selection: ResumeSelection) {
        self.highlighted = selection;
        self.selection = Some(selection);
        if selection == ResumeSelection::Continue {
            self.app_event_tx
                .send(AppEvent::QueueUserText(continue_prompt()));
        }
    }
}

impl BottomPaneView for ResumePromptOverlay {
    fn handle_key_event(&mut self, key_event: KeyEvent) {
        if key_event.kind == KeyEventKind::Release {
            return;
        }
        if key_event.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key_event.code, KeyCode::Char('c') | KeyCode::Char('d'))
        {
            self.select(ResumeSelection::ResumePaused);
            return;
        }

        match key_event.code {
            KeyCode::Up | KeyCode::Char('k') => self.highlighted = self.highlighted.prev(),
            KeyCode::Down | KeyCode::Char('j') => self.highlighted = self.highlighted.next(),
            KeyCode::Char('1') => self.select(ResumeSelection::ResumePaused),
            KeyCode::Char('2') => self.select(ResumeSelection::Continue),
            KeyCode::Enter => self.select(self.highlighted),
            KeyCode::Esc => self.select(ResumeSelection::ResumePaused),
            _ => {}
        }
    }

    fn is_complete(&self) -> bool {
        self.selection.is_some()
    }

    fn on_ctrl_c(&mut self) -> CancellationEvent {
        self.select(ResumeSelection::ResumePaused);
        CancellationEvent::Handled
    }
}

impl crate::render::renderable::Renderable for ResumePromptOverlay {
    fn render(&self, area: Rect, buf: &mut Buffer) {
        Clear.render(area, buf);
        let block = Block::bordered().title("Resume".bold());
        let inner = block.inner(area);
        block.render(area, buf);

        let inset = inner.inset(Insets::vh(1, 2));
        let [header_area, options_area] =
            Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(inset);

        let mut header = Vec::new();
        header.push(Line::from(vec![
            "Previous turn was interrupted.".bold(),
            " ".into(),
            "Nothing will run until you choose.".dim(),
        ]));
        if self.had_partial_output || self.had_in_progress_tools {
            let mut details = Vec::new();
            if self.had_partial_output {
                details.push("partial assistant output".to_string());
            }
            if self.had_in_progress_tools {
                details.push("in-progress tool calls".to_string());
            }
            header.push(Line::from(vec![
                "Detected: ".dim(),
                details.join(", ").into(),
            ]));
        }
        header.push(Line::from(vec![
            "Tip: ".dim(),
            "Continue sends a new message; it does not auto-replay tool calls.".dim(),
        ]));

        for (i, line) in header.into_iter().enumerate() {
            let y = header_area.y.saturating_add(i as u16);
            let bottom = header_area.y.saturating_add(header_area.height);
            if y >= bottom {
                break;
            }
            let line_area = Rect {
                x: header_area.x,
                y,
                width: header_area.width,
                height: 1,
            };
            line.render(line_area, buf);
        }

        let [opt0_area, opt1_area] =
            Layout::vertical([Constraint::Length(2), Constraint::Length(2)]).areas(options_area);

        let option_0 = selection_option_row(
            0,
            "Resume paused (recommended)".to_string(),
            self.highlighted == ResumeSelection::ResumePaused,
        );
        option_0.render(opt0_area, buf);

        let option_1 = selection_option_row(
            1,
            "Continue from where you left off".to_string(),
            self.highlighted == ResumeSelection::Continue,
        );
        option_1.render(opt1_area, buf);
    }

    fn desired_height(&self, _width: u16) -> u16 {
        9
    }
}

fn continue_prompt() -> String {
    "Continue from where you left off. Do not re-run tool calls that already completed; use the outputs above. If you need to rerun a tool, ask first."
        .to_string()
}
