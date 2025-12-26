use codex_lsp::Diagnostic;
use codex_lsp::DiagnosticSeverity;

pub(crate) fn render_diagnostics_summary(diags: &[Diagnostic]) -> String {
    let mut errors = 0usize;
    let mut warnings = 0usize;
    let mut infos = 0usize;
    let mut hints = 0usize;
    for d in diags {
        match d.severity {
            Some(DiagnosticSeverity::Error) => errors += 1,
            Some(DiagnosticSeverity::Warning) => warnings += 1,
            Some(DiagnosticSeverity::Information) => infos += 1,
            Some(DiagnosticSeverity::Hint) => hints += 1,
            None => {}
        }
    }

    let mut lines = Vec::new();
    lines.push("## LSP diagnostics".to_string());
    lines.push(format!(
        "Errors: {errors}, Warnings: {warnings}, Info: {infos}, Hint: {hints}"
    ));
    lines.push("Diagnostics use 1-based line/character positions.".to_string());
    lines.push("".to_string());
    for d in diags {
        lines.push(format!(
            "- {path}:{line}:{character} {message}",
            path = d.path,
            line = d.range.start.line,
            character = d.range.start.character,
            message = d.message
        ));
    }
    lines.join("\n")
}
