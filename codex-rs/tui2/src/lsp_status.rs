use codex_lsp::LspServerSource;
use codex_lsp::LspStatus;
use ratatui::style::Style;
use ratatui::style::Stylize as _;
use ratatui::text::Line;
use ratatui::text::Span;

pub(crate) fn render(status: &LspStatus) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(Line::from("LSP status".bold()));

    let enabled = status.enabled.to_string();
    lines.push(vec!["enabled: ".dim(), enabled.into()].into());

    lines.push(vec!["root: ".dim(), status.root.display().to_string().into()].into());

    let workspace = if status.workspace_initialized {
        "initialized".to_string()
    } else {
        "not initialized".to_string()
    };
    lines.push(vec!["workspace: ".dim(), workspace.into()].into());

    if !status.ignored_globs.is_empty() {
        lines.push(vec!["ignored: ".dim(), status.ignored_globs.join(", ").into()].into());
    }

    lines.push(
        vec![
            "max_file_bytes: ".dim(),
            status.max_file_bytes.to_string().into(),
        ]
        .into(),
    );

    lines.push(Line::from(""));
    lines.push(Line::from("Servers".bold()));

    for lang in &status.languages {
        let header = vec![
            "• ".into(),
            Span::from(lang.language_id.clone()).bold(),
            "  ".into(),
            "running=".dim(),
            if lang.running {
                "yes".green()
            } else {
                "no".dim()
            },
        ];
        lines.push(header.into());

        let effective = lang.effective.as_ref().map(|(cfg, source)| {
            let source = match source {
                LspServerSource::Config => "config",
                LspServerSource::Autodetect => "autodetect",
            };
            format!("{} ({source})", cfg.command)
        });
        lines.extend(render_kv(
            "effective",
            effective.as_deref().unwrap_or("(none)"),
            2,
        ));
        if let Some((cfg, _)) = &lang.effective
            && !cfg.args.is_empty() {
                lines.extend(render_kv("args", &cfg.args.join(" "), 2));
            }

        if let Some(cfg) = &lang.configured {
            lines.extend(render_kv("configured", &cfg.command, 2));
            if !cfg.args.is_empty() {
                lines.extend(render_kv("args", &cfg.args.join(" "), 2));
            }
        } else {
            lines.extend(render_kv("configured", "(none)", 2));
        }

        match (&lang.autodetected, &lang.effective) {
            (Some(det), Some((eff, LspServerSource::Autodetect)))
                if det.command == eff.command && det.args == eff.args => {}
            (Some(det), _) => {
                lines.extend(render_kv("detected", &det.command, 2));
                if !det.args.is_empty() {
                    lines.extend(render_kv("args", &det.args.join(" "), 2));
                }
            }
            (None, _) => {
                lines.extend(render_kv("detected", "(not found on PATH)", 2));
            }
        }

        lines.push(Line::from(""));
    }

    while matches!(lines.last(), Some(line) if line.spans.is_empty()) {
        lines.pop();
    }

    lines
}

fn render_kv(key: &str, value: &str, indent: usize) -> Vec<Line<'static>> {
    let prefix = " ".repeat(indent);
    let key = format!("{prefix}{key}: ");

    let key_span: Span<'static> = Span::styled(key, Style::new().dim());
    let value_span: Span<'static> = if value.starts_with('(') {
        Span::styled(value.to_string(), Style::new().dim())
    } else {
        Span::from(value.to_string())
    };

    vec![vec![key_span, value_span].into()]
}
