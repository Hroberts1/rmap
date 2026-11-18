//! Drawing for the export dialog, the saved-scan picker and the diff screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap};
use rmap_report::{DiffKind, ExportFormat};

use crate::report::{ComparePicker, Dialog, DiffView, ExportDialog};
use crate::ui::{ACCENT, centered, key_help};

pub fn draw_dialog(frame: &mut Frame, dialog: &Dialog) {
    match dialog {
        Dialog::Export(d) => draw_export(frame, d),
        Dialog::Compare(p) => draw_picker(frame, p),
    }
}

fn draw_export(frame: &mut Frame, d: &ExportDialog) {
    let area = centered(
        frame.area(),
        72.min(frame.area().width),
        10.min(frame.area().height),
    );
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .title(" export ".bold().fg(ACCENT))
        .border_style(Style::new().fg(ACCENT))
        .title_bottom(
            key_help(&[("Enter", "export"), ("Tab", "format"), ("Esc", "close")]).centered(),
        );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [format, path, _, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .horizontal_margin(1)
    .vertical_margin(u16::from(inner.height > 5))
    .areas(inner);

    let formats: Vec<Span> = [ExportFormat::Json, ExportFormat::Xml]
        .into_iter()
        .flat_map(|f| {
            let s = format!(" {} ", f.label());
            let span = if f == d.format {
                Span::styled(s, Style::new().fg(Color::Black).bg(ACCENT).bold())
            } else {
                Span::raw(s).dim()
            };
            [span, Span::raw(" ")]
        })
        .collect();
    let mut line = vec![Span::raw("Format  ").dim()];
    line.extend(formats);
    frame.render_widget(Paragraph::new(Line::from(line)), format);

    // Long paths scroll sideways so the cursor stays on screen.
    const LABEL_W: u16 = 8;
    let (shown, cursor) = d.path.window(path.width.saturating_sub(LABEL_W) as usize);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("Path    ").dim(),
            Span::raw(shown),
        ])),
        path,
    );
    if path.height > 0 && path.width > 0 {
        let x = path.x + LABEL_W + cursor as u16;
        frame.set_cursor_position((x.min(path.right().saturating_sub(1)), path.y));
    }

    let msg = match &d.status {
        Some(Ok(p)) => Line::from(format!("✓ saved to {p}")).fg(Color::Green),
        Some(Err(e)) => Line::from(format!("✗ {e}")).fg(Color::Red),
        None => Line::from("Nmap XML can be read by tools that import Nmap results.").dim(),
    };
    frame.render_widget(Paragraph::new(msg).wrap(Wrap { trim: true }), status);
}

fn draw_picker(frame: &mut Frame, p: &ComparePicker) {
    let area = centered(
        frame.area(),
        90.min(frame.area().width),
        (p.scans.len() as u16 + 4)
            .clamp(6, 20)
            .min(frame.area().height),
    );
    frame.render_widget(Clear, area);
    let items: Vec<ListItem> = p
        .scans
        .iter()
        .map(|s| {
            let same = s.report.config.targets.trim() == p.current.config.targets.trim();
            let line = Line::from(s.summary());
            ListItem::new(if same { line } else { line.dim() })
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::bordered()
                .title(" compare with a saved scan ".bold().fg(ACCENT))
                .border_style(Style::new().fg(ACCENT))
                .title_bottom(
                    key_help(&[("↑↓", "select"), ("Enter", "compare"), ("Esc", "cancel")])
                        .centered(),
                ),
        )
        .highlight_style(
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▌");
    let mut state = ListState::default().with_selected(Some(p.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

pub fn draw_diff(frame: &mut Frame, view: &DiffView) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let block = Block::bordered()
        .title(Line::from(vec![
            " rmap ".bold().fg(ACCENT),
            Span::raw("· compare "),
        ]))
        .title(
            Line::from(format!(
                " {} change{} ",
                view.changes,
                if view.changes == 1 { "" } else { "s" }
            ))
            .bold()
            .fg(if view.changes == 0 {
                Color::Green
            } else {
                Color::Yellow
            })
            .right_aligned(),
        );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![Span::raw(" was ").dim(), Span::raw(view.old.clone())]),
            Line::from(vec![Span::raw(" now ").dim(), Span::raw(view.new.clone())]),
        ])
        .block(block),
        header,
    );

    let lines: Vec<Line> = view
        .lines
        .iter()
        .map(|l| {
            let line = Line::from(l.text.clone());
            match l.kind {
                DiffKind::Heading => line.bold().fg(ACCENT),
                DiffKind::Added => line.fg(Color::Green),
                DiffKind::Removed => line.fg(Color::Red),
                DiffKind::Changed => line.fg(Color::Yellow),
                DiffKind::Note => line.dim(),
            }
        })
        .collect();
    let scroll = view.scroll.min(u16::MAX as usize) as u16;
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .block(Block::bordered().title(" changes ")),
        body,
    );
    frame.render_widget(
        Paragraph::new(key_help(&[
            ("↑↓", "scroll"),
            ("Esc", "back"),
            ("q", "quit"),
        ])),
        footer,
    );
}
