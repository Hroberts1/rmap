//! Rendering. Pure functions of `App` state; no side effects beyond the frame.

use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Clear, Gauge, Paragraph, Row, Table, TableState, Wrap};
use rmap_core::{HostState, PortState, Service, Timing, VulnSeverity, Vulnerability, service_name};

use crate::app::{App, Confirm, Field, HostRow, Pane, ScanView, Screen};
use crate::input::TextInput;

pub(crate) const ACCENT: Color = Color::Cyan;

pub fn draw(frame: &mut Frame, app: &mut App) {
    match app.screen {
        Screen::Setup => draw_setup(frame, app),
        Screen::Results => {
            if let Some(view) = app.scan.as_mut() {
                draw_results(frame, view);
            }
            if app.help {
                draw_help(frame);
            }
        }
        Screen::Diff => {
            if let Some(diff) = app.diff.as_ref() {
                crate::report_ui::draw_diff(frame, diff);
            }
        }
    }
    if let Some(dialog) = &app.dialog {
        crate::report_ui::draw_dialog(frame, dialog);
    }
    if let Some((_, public)) = &app.pending {
        draw_public_warning(frame, public);
    }
    if let Some(confirm) = app.confirm {
        draw_yes_no(frame, confirm);
    }
}

pub(crate) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    area
}

pub(crate) fn key_help(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, what) in pairs {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::new().fg(Color::Black).bg(ACCENT),
        ));
        spans.push(Span::raw(format!(" {what}  ")));
    }
    Line::from(spans)
}

// ---------------------------------------------------------------- setup ---

fn draw_setup(frame: &mut Frame, app: &App) {
    let form = &app.form;
    let area = centered(
        frame.area(),
        76.min(frame.area().width),
        22.min(frame.area().height),
    );
    let block = Block::bordered()
        .title(Line::from(" rmap · new scan ").bold().fg(ACCENT))
        .title_bottom(key_help(&[("Tab", "next"), ("Enter", "scan"), ("Esc", "quit")]).centered());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [
        targets,
        targets_hint,
        ports,
        ports_hint,
        scan_type,
        timing,
        timing_hint,
        discovery,
        services,
        vulns,
        _,
        error,
        log_line,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .margin(1)
    .areas(inner);

    let label = |field: Field, text: &'static str| {
        let style = if form.focus == field {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::DIM)
        };
        Span::styled(format!("{text:>11}  "), style)
    };
    let hint = |text: &'static str| Paragraph::new(Line::from(format!("{:13}{text}", "")).dim());

    let text_field =
        |frame: &mut Frame, area: Rect, field: Field, name, value: &TextInput, placeholder| {
            // Long input scrolls sideways so the cursor stays on screen.
            let (window, cursor) = value.window(area.width.saturating_sub(13) as usize);
            let shown = if value.is_empty() {
                Span::raw(placeholder).dim().italic()
            } else {
                Span::raw(window)
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![label(field, name), shown])),
                area,
            );
            if form.focus == field {
                let x = area.x + 13 + cursor as u16;
                frame.set_cursor_position((x.min(area.right().saturating_sub(1)), area.y));
            }
        };

    text_field(
        frame,
        targets,
        Field::Targets,
        "Targets",
        &form.targets,
        "192.168.1.0/24",
    );
    frame.render_widget(
        hint("CIDR, ranges (10.0.0.1-50), hostnames; comma separated"),
        targets_hint,
    );
    text_field(frame, ports, Field::Ports, "Ports", &form.ports, "common");
    frame.render_widget(hint("22,80,443 · 1-1024 · common · all"), ports_hint);

    let kind = form.scan_type;
    let mut kind_spans = vec![
        label(Field::ScanType, "Scan type"),
        Span::raw(format!("◂ {} ▸", kind.label())).bold(),
    ];
    if kind.needs_raw_sockets() {
        kind_spans.push(Span::raw("  needs root / CAP_NET_RAW, else falls back").fg(Color::Yellow));
    }
    frame.render_widget(Paragraph::new(Line::from(kind_spans)), scan_type);

    let t = Timing::template(form.timing);
    let pips: String = (0..=5)
        .map(|i| if i == form.timing { '●' } else { '○' })
        .collect();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            label(Field::Timing, "Timing"),
            Span::raw(format!("◂ T{} {} ▸  ", t.level, t.name)).bold(),
            Span::raw(pips).fg(ACCENT),
        ])),
        timing,
    );
    let timing_desc = format!(
        "{:13}{} probes in flight · {}ms timeout · {} retr{}",
        "",
        t.concurrency,
        t.connect_timeout.as_millis(),
        t.retries,
        if t.retries == 1 { "y" } else { "ies" }
    );
    frame.render_widget(Paragraph::new(Line::from(timing_desc).dim()), timing_hint);

    let check = if form.discovery {
        "[x] ping hosts first, skip ones that don't answer"
    } else {
        "[ ] scan every address, even if it seems down"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            label(Field::Discovery, "Discovery"),
            Span::raw(check),
        ])),
        discovery,
    );

    let services_check = if form.service_detection {
        "[x] identify software and versions on open ports"
    } else {
        "[ ] report open ports only"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            label(Field::Services, "Services"),
            Span::raw(services_check),
        ])),
        services,
    );

    // Vulns depends on Services (ticking it turns Services on), so with
    // Services off it reads as unavailable rather than as a live choice.
    let vulns_check = if form.vuln_matching {
        Span::raw("[x] flag potential CVEs for identified services")
    } else if form.service_detection {
        Span::raw("[ ] don't check for known vulnerabilities")
    } else {
        Span::raw("[ ] needs Services (ticking this turns it on)").dim()
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![label(Field::Vulns, "Vulns"), vulns_check])),
        vulns,
    );

    if let Some(err) = &form.error {
        frame.render_widget(
            Paragraph::new(Line::from(format!("✗ {err}")).fg(Color::Red)).wrap(Wrap { trim: true }),
            error,
        );
    }

    let log_text = match rmap_log::log_path() {
        Some(path) => format!("log: {}", path.display()),
        None => "logging off (set RMAP_LOG=info to enable)".into(),
    };
    frame.render_widget(
        Paragraph::new(Line::from(log_text).dim().italic()),
        log_line,
    );
}

// -------------------------------------------------------------- results ---

/// Below this width the host list and details stack vertically, so the
/// host table gets the full width instead of a third of it.
const STACK_BELOW: u16 = 100;
/// Most log lines shown under the results; the panel shrinks to fit fewer.
const LOG_ROWS: usize = 3;

fn draw_results(frame: &mut Frame, view: &mut ScanView) {
    let log_height = match view.log.len().min(LOG_ROWS) {
        0 => 0,
        n => n as u16 + 2,
    };
    let [header, body, log, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(5),
        Constraint::Length(log_height),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, header, view);
    let [hosts, detail] = if body.width < STACK_BELOW {
        // Hosts on top, sized to the list but never more than ~40%.
        let max = (body.height * 2 / 5).max(3);
        let want = view.visible().len() as u16 + 3;
        Layout::vertical([Constraint::Length(want.clamp(3, max)), Constraint::Min(0)]).areas(body)
    } else {
        Layout::horizontal([Constraint::Percentage(36), Constraint::Percentage(64)]).areas(body)
    };
    draw_host_table(frame, hosts, view);
    draw_host_detail(frame, detail, view);
    if log_height > 0 {
        draw_log(frame, log, view);
    }
    frame.render_widget(Paragraph::new(footer_help(view, footer.width)), footer);
}

/// The footer key strip, trimmed to fit: `? help` and `q quit` always show,
/// the rest are dropped from the end as the terminal narrows.
fn footer_help(view: &ScanView, width: u16) -> Line<'static> {
    let mut wanted = vec![("Tab", "pane"), ("↑↓", "select")];
    if view.is_running() {
        wanted.push(("s", "stop"));
    }
    wanted.extend([
        ("e", "export"),
        ("n", "new scan"),
        ("c", "compare"),
        ("d", "down hosts"),
    ]);
    let always = [("?", "help"), ("q", "quit")];
    // key_help draws each pair as " key " + " what  ".
    let cost = |(k, w): &(&str, &str)| k.chars().count() + w.chars().count() + 5;
    let mut room = (width as usize).saturating_sub(always.iter().map(cost).sum());
    let mut shown = Vec::new();
    for pair in wanted {
        if cost(&pair) > room {
            break;
        }
        room -= cost(&pair);
        shown.push(pair);
    }
    shown.extend(always);
    key_help(&shown)
}

fn draw_header(frame: &mut Frame, area: Rect, view: &ScanView) {
    let (status, color) = if view.failed {
        ("failed", Color::Red)
    } else if view.stopped {
        ("stopped", Color::Yellow)
    } else if view.finished.is_some() {
        ("done", Color::Green)
    } else {
        ("scanning", ACCENT)
    };
    let block = Block::bordered()
        .title(Line::from(vec![
            " rmap ".bold().fg(ACCENT),
            Span::raw(format!("· {} ", view.summary)),
        ]))
        .title(Line::from(format!(" {status} ").bold().fg(color)).right_aligned());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [stats, gauge] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(inner);
    let up = view.count(HostState::Up) + view.count(HostState::Assumed);
    let down = view.count(HostState::Down);
    let open: usize = view.hosts.values().map(|h| h.open.len()).sum();
    let cves: usize = view
        .hosts
        .values()
        .flat_map(|h| &h.open)
        .map(|p| p.vulnerabilities.len())
        .sum();
    let mut spans = vec![
        Span::raw(format!(" {up} up")).fg(Color::Green).bold(),
        Span::raw(format!(" · {down} down")).dim(),
        Span::raw(format!(
            " · {} of {} hosts seen",
            view.hosts.len(),
            view.total_hosts
        )),
        Span::raw(format!(" · {open} open ports")).fg(ACCENT),
    ];
    if cves > 0 {
        spans.push(Span::raw(format!(" · {cves} potential CVEs")).fg(Color::Red));
    }
    spans.push(Span::raw(format!(" · {}", fmt_elapsed(view.elapsed()))));
    frame.render_widget(Paragraph::new(Line::from(spans)), stats);

    let progress = &view.scan.progress;
    let done = progress
        .completed
        .load(std::sync::atomic::Ordering::Relaxed);
    let total = progress.total.load(std::sync::atomic::Ordering::Relaxed);
    frame.render_widget(
        Gauge::default()
            .gauge_style(Style::new().fg(color).bg(Color::DarkGray))
            .ratio(progress.ratio())
            .label(format!("{done} / {total} probes")),
        gauge,
    );
}

/// Highlight for the selected row. REVERSED works on light and dark
/// themes alike; a hardcoded background colour doesn't.
fn highlight(focused: bool) -> Style {
    if focused {
        Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::new().add_modifier(Modifier::BOLD)
    }
}

fn pane_block(title: impl Into<Line<'static>>, focused: bool) -> Block<'static> {
    let block = Block::bordered().title(title);
    if focused {
        block.border_style(Style::new().fg(ACCENT))
    } else {
        block
    }
}

fn draw_host_table(frame: &mut Frame, area: Rect, view: &ScanView) {
    let visible = view.visible();
    let focused = view.focus == Pane::Hosts;

    // Fixed widths for address and open count; the name gets what's left,
    // and RTT only shows when the name still has room after it.
    // Width inside the borders, less the highlight-symbol column.
    let inner = area.width.saturating_sub(3) as usize;
    let addr_w = visible
        .iter()
        .map(|ip| ip.to_string().len())
        .max()
        .unwrap_or(0)
        .max("ADDRESS".len());
    const OPEN_W: usize = 4;
    const RTT_W: usize = 7;
    let mut name_w = inner.saturating_sub(1 + addr_w + OPEN_W + 3);
    let show_rtt = name_w > 12 + RTT_W;
    if show_rtt {
        name_w -= RTT_W + 1;
    }
    // No wider than the longest name, so OPEN stays next to it.
    let longest = visible
        .iter()
        .filter_map(|ip| view.hosts[ip].hostname.as_deref())
        .map(|n| n.chars().count())
        .max()
        .unwrap_or(0)
        .max("NAME".len());
    name_w = name_w.min(longest);

    let rows = visible.iter().map(|ip| {
        let h = &view.hosts[ip];
        let (mark, style) = match h.state {
            HostState::Up | HostState::Assumed if !h.open.is_empty() => {
                ("●", Style::new().fg(Color::Green))
            }
            HostState::Up | HostState::Assumed => ("●", Style::new().fg(Color::Yellow)),
            HostState::Down => ("○", Style::new().add_modifier(Modifier::DIM)),
        };
        let mut open = vec![if h.done || !h.open.is_empty() {
            Span::raw(h.open.len().to_string()).fg(ACCENT)
        } else {
            Span::raw("…").fg(ACCENT)
        }];
        if h.open.iter().any(|p| !p.vulnerabilities.is_empty()) {
            open.push(Span::raw(" !").fg(Color::Red).bold());
        }
        let name = h.hostname.as_deref().unwrap_or_default();
        let mut cells = vec![
            Cell::from(mark).style(style),
            Cell::from(ip.to_string()),
            Cell::from(ellipsize(name, name_w)).dim(),
            Cell::from(Line::from(open)),
        ];
        if show_rtt {
            cells.push(Cell::from(h.rtt.map(fmt_rtt).unwrap_or_default()).dim());
        }
        Row::new(cells).style(if h.state == HostState::Down {
            Style::new().dim()
        } else {
            Style::new()
        })
    });

    let title = if view.show_down {
        " hosts (all) "
    } else {
        " hosts (up) "
    };
    let mut widths = vec![
        Constraint::Length(1),
        Constraint::Length(addr_w as u16),
        Constraint::Length(name_w as u16),
        Constraint::Length(OPEN_W as u16),
    ];
    let mut header = vec!["", "ADDRESS", "NAME", "OPEN"];
    if show_rtt {
        widths.push(Constraint::Length(RTT_W as u16));
        header.push("RTT");
    }
    let table = Table::new(rows, widths)
        .header(Row::new(header).bold().dim())
        .block(pane_block(title, focused))
        .row_highlight_style(highlight(focused))
        .highlight_symbol("▌");

    let mut state = TableState::default().with_selected(
        view.selected
            .and_then(|s| visible.iter().position(|ip| *ip == s)),
    );
    frame.render_stateful_widget(table, area, &mut state);

    if visible.is_empty() {
        let msg = if view.is_running() {
            "waiting for hosts…"
        } else {
            "no hosts up"
        };
        let inner = centered(area, msg.len() as u16, 1);
        frame.render_widget(Paragraph::new(msg).dim(), inner);
    }
}

/// `open|filtered` is 13 columns for one rare state; show it as `open?`
/// and explain it in the pane footer.
fn state_label(state: PortState) -> &'static str {
    match state {
        PortState::OpenFiltered => "open?",
        other => other.as_str(),
    }
}

fn draw_host_detail(frame: &mut Frame, area: Rect, view: &mut ScanView) {
    let focused = view.focus == Pane::Ports;
    let Some((ip, host)) = view
        .selected
        .and_then(|ip| view.hosts.get(&ip).map(|h| (ip, h)))
    else {
        frame.render_widget(pane_block(" details ", focused), area);
        return;
    };
    let title = match &host.hostname {
        Some(name) => format!("{ip} · {name}"),
        None => ip.to_string(),
    };
    let title = format!(
        " {} ",
        ellipsize(&title, area.width.saturating_sub(4) as usize)
    );
    let block = pane_block(title, focused).padding(ratatui::widgets::Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [info, ports, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    frame.render_widget(Paragraph::new(host_info(host)), info);

    // Column plan. Detail and CVE lines span from SERVICE to the right
    // edge (Cell::column_span) and wrap, instead of being squeezed into
    // the VERSION column.
    const PORT_W: usize = 9; // "65535/tcp"
    const STATE_W: usize = 6; // "closed", "open?"
    const SERVICE_W: usize = 12;
    const RTT_W: usize = 7;
    let width = ports.width as usize;
    let show_rtt = width >= PORT_W + STATE_W + SERVICE_W + RTT_W + 4 + 24;
    let ncols: u16 = if show_rtt { 5 } else { 4 };
    let span_w = width.saturating_sub(PORT_W + STATE_W + 2);

    let mut rows: Vec<Row> = Vec::new();
    let mut heights: Vec<usize> = Vec::new();
    // First and last table row of each port's group.
    let mut groups: Vec<(usize, usize)> = Vec::new();
    for p in &host.open {
        let first = rows.len();
        let state_color = match p.state {
            PortState::Open => Color::Green,
            _ => Color::Yellow,
        };
        let (name, version) = match &p.service {
            Some(s) => (s.name.clone(), s.version_label().unwrap_or_default()),
            None => (
                service_name(p.port).unwrap_or("unknown").to_string(),
                String::new(),
            ),
        };
        let mut cells = vec![
            Cell::from(format!("{}/{}", p.port, p.protocol.as_str())),
            Cell::from(state_label(p.state)).fg(state_color),
            Cell::from(name),
            Cell::from(version),
        ];
        if show_rtt {
            cells.push(Cell::from(p.rtt.map(fmt_rtt).unwrap_or_default()).dim());
        }
        rows.push(Row::new(cells));
        heights.push(1);

        if let Some(d) = p.service.as_ref().and_then(service_detail) {
            let lines: Vec<Line> = wrap(&d, span_w, 2).into_iter().map(Line::from).collect();
            heights.push(lines.len());
            rows.push(spanning_row(Text::from(lines), ncols).dim());
        }
        for v in &p.vulnerabilities {
            let text = vuln_text(v, span_w);
            heights.push(text.lines.len());
            rows.push(spanning_row(text, ncols));
        }
        groups.push((first, rows.len() - 1));
    }

    // Scroll only as far as needed to keep the selected port's whole group
    // (its detail and CVE lines too) on screen.
    let body = ports.height.saturating_sub(1) as usize; // less the header
    let selected_row = if groups.is_empty() {
        view.port_selected = 0;
        view.port_offset = 0;
        None
    } else {
        view.port_selected = view.port_selected.min(groups.len() - 1);
        let (first, last) = groups[view.port_selected];
        let mut offset = view.port_offset.min(first);
        while offset < first && heights[offset..=last].iter().sum::<usize>() > body {
            offset += 1;
        }
        view.port_offset = offset;
        Some(first)
    };
    let below = heights.iter().skip(view.port_offset).sum::<usize>() > body;
    let above = view.port_offset > 0;

    let mut widths = vec![
        Constraint::Length(PORT_W as u16),
        Constraint::Length(STATE_W as u16),
        Constraint::Length(SERVICE_W as u16),
        Constraint::Fill(1),
    ];
    let mut header = vec!["PORT", "STATE", "SERVICE", "VERSION"];
    if show_rtt {
        widths.push(Constraint::Length(RTT_W as u16));
        header.push("RTT");
    }
    let table = Table::new(rows, widths)
        .header(Row::new(header).bold().dim())
        .row_highlight_style(highlight(true));
    let mut state = TableState::default()
        .with_offset(view.port_offset)
        .with_selected(selected_row.filter(|_| focused));
    frame.render_stateful_widget(table, ports, &mut state);

    let mut notes: Vec<String> = Vec::new();
    match (above, below) {
        (true, true) => notes.push("↑↓ more".into()),
        (true, false) => notes.push("↑ more".into()),
        (false, true) => notes.push("↓ more".into()),
        (false, false) => {}
    }
    if host.done {
        notes.push(format!(
            "not shown: {} closed, {} filtered",
            host.closed, host.filtered
        ));
    } else if host.state != HostState::Down {
        notes.push("scanning…".into());
    }
    if host.open.iter().any(|p| p.state == PortState::OpenFiltered) {
        notes.push("open? = open|filtered".into());
    }
    frame.render_widget(Paragraph::new(notes.join(" · ")).dim(), footer);
}

/// A row whose content spans every column after PORT and STATE.
fn spanning_row(text: Text<'static>, ncols: u16) -> Row<'static> {
    let height = text.lines.len().max(1) as u16;
    // Cell::from("") is a real empty cell; Cell::default() has span 0.
    Row::new(vec![
        Cell::from(""),
        Cell::from(""),
        Cell::from(text).column_span(ncols - 2),
    ])
    .height(height)
}

/// A potential CVE: a severity label (text, not just colour, so it reads
/// without colour too), the score, then the ID and wrapped summary.
fn vuln_text(v: &Vulnerability, width: usize) -> Text<'static> {
    let (label, color) = match v.severity {
        VulnSeverity::Critical => ("CRIT", Color::Red),
        VulnSeverity::High => ("HIGH", Color::Red),
        VulnSeverity::Medium => ("MED", Color::Yellow),
        VulnSeverity::Low => ("LOW", Color::Gray),
    };
    let mut head_style = Style::new().fg(color);
    if v.severity == VulnSeverity::Critical {
        head_style = head_style.add_modifier(Modifier::BOLD);
    }
    let score = v.score.map(|s| format!("{s:.1}")).unwrap_or_default();
    let head = format!("{label:<4} {score:>4}  ");
    let indent = head.chars().count();
    let body = format!("{}  {}", v.id, v.summary);
    let lines = wrap(&body, width.saturating_sub(indent), 0)
        .into_iter()
        .enumerate()
        .map(|(i, line)| {
            let lead = if i == 0 {
                Span::styled(head.clone(), head_style)
            } else {
                Span::raw(" ".repeat(indent))
            };
            Line::from(vec![lead, Span::raw(line).fg(color)])
        })
        .collect::<Vec<_>>();
    Text::from(lines)
}

/// Word-wrap `text` to `width` columns, indenting continuation lines by
/// `indent`. Words longer than a line are split. Too narrow to wrap
/// usefully: returns the text as one line and lets the table clip it.
fn wrap(text: &str, width: usize, indent: usize) -> Vec<String> {
    if width < indent + 10 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut len = 0;
    let mut fresh = true; // nothing but indent on this line yet
    for word in text.split_whitespace() {
        let mut chars: Vec<char> = word.chars().collect();
        loop {
            let gap = usize::from(!fresh);
            let room = width - len;
            if chars.len() + gap <= room {
                if !fresh {
                    line.push(' ');
                }
                line.extend(&chars);
                len += chars.len() + gap;
                fresh = false;
                break;
            }
            if fresh {
                line.extend(chars.drain(..room));
            }
            lines.push(std::mem::take(&mut line));
            line = " ".repeat(indent);
            len = indent;
            fresh = true;
        }
    }
    if !fresh || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn ellipsize(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else if width == 0 {
        String::new()
    } else {
        s.chars().take(width - 1).chain(['…']).collect()
    }
}

/// Extra detection results for a port, on one line: info, OS hint and the
/// CPE (without its trailing wildcards).
fn service_detail(s: &Service) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(info) = &s.info {
        parts.push(info.clone());
    }
    if let Some(os) = &s.os_hint {
        parts.push(format!("os: {os}"));
    }
    if let Some(cpe) = s.cpes.first() {
        parts.push(cpe.trim_end_matches(":*").to_string());
    }
    (!parts.is_empty()).then(|| format!("└ {}", parts.join(" · ")))
}

fn host_info(h: &HostRow) -> Line<'static> {
    let state = match h.state {
        HostState::Up => Span::raw("up").fg(Color::Green),
        HostState::Assumed => Span::raw("assumed up (discovery off)").fg(Color::Yellow),
        HostState::Down => Span::raw("down (no response)").dim(),
    };
    let mut spans = vec![Span::raw("state ").dim(), state];
    if let Some(rtt) = h.rtt {
        spans.push(Span::raw(format!("  latency {}", fmt_rtt(rtt))).dim());
    }
    Line::from(spans)
}

fn draw_log(frame: &mut Frame, area: Rect, view: &ScanView) {
    let height = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = view
        .log
        .iter()
        .rev()
        .take(height)
        .rev()
        .map(|l| {
            if l.starts_with(crate::app::WARNING_PREFIX) {
                Line::from(l.clone()).fg(Color::Yellow)
            } else {
                Line::from(l.clone()).dim()
            }
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" log ")),
        area,
    );
}

fn draw_help(frame: &mut Frame) {
    const KEYS: &[(&str, &str)] = &[
        ("↑↓ j k", "move in the focused pane"),
        ("PgUp PgDn", "move by 10"),
        ("Home End g G", "first / last"),
        ("Tab ← → h l", "switch between hosts and ports"),
        ("d", "show or hide down hosts"),
        ("s", "stop the scan"),
        ("e", "export JSON / XML"),
        ("c", "compare with a saved scan"),
        ("y", "copy IP (or ip:port) to clipboard"),
        ("Y", "copy CVE IDs (port, or whole host)"),
        ("n Esc", "new scan"),
        ("q", "quit"),
        ("Ctrl-C", "quit immediately"),
    ];
    let mut lines: Vec<Line> = KEYS
        .iter()
        .map(|(k, what)| {
            Line::from(vec![
                Span::raw(format!("{k:>13}  ")).fg(ACCENT).bold(),
                Span::raw(*what),
            ])
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(" open? = open|filtered: no reply, may be open").dim());
    lines.push(Line::from(" !     = host has potential CVEs").dim());
    let area = centered(
        frame.area(),
        52.min(frame.area().width),
        (lines.len() as u16 + 2).min(frame.area().height),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" keys ".bold().fg(ACCENT))
                .title_bottom(Line::from(" any key closes ").dim().centered()),
        ),
        area,
    );
}

fn draw_yes_no(frame: &mut Frame, confirm: Confirm) {
    let question = confirm.question();
    let area = centered(
        frame.area(),
        (question.chars().count() as u16 + 6).min(frame.area().width),
        5.min(frame.area().height),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(question).centered(),
            Line::default(),
            key_help(&[("y", "yes"), ("n", "no")]).centered(),
        ])
        .block(
            Block::bordered()
                .title(" confirm ".bold().fg(Color::Yellow))
                .border_style(Style::new().fg(Color::Yellow)),
        ),
        area,
    );
}

fn draw_public_warning(frame: &mut Frame, public: &[String]) {
    let area = centered(
        frame.area(),
        64.min(frame.area().width),
        11.min(frame.area().height),
    );
    frame.render_widget(Clear, area);
    let mut listed = public
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if public.len() > 3 {
        listed.push_str(&format!(" and {} more", public.len() - 3));
    }
    let text = vec![
        Line::from("These targets include public addresses:"),
        Line::from(listed).bold(),
        Line::default(),
        Line::from("Only scan networks you own or have written permission"),
        Line::from("to test. Unauthorized scanning may be illegal."),
        Line::default(),
        key_help(&[("y", "I'm authorized, scan"), ("n", "go back")]),
    ];
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: true }).block(
            Block::bordered()
                .title(" confirm ".bold().fg(Color::Yellow))
                .border_style(Style::new().fg(Color::Yellow)),
        ),
        area,
    );
}

fn fmt_rtt(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 10.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{ms:.0}ms")
    }
}

fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_detail_line() {
        let mut s = Service {
            name: "ssh".into(),
            ..Default::default()
        };
        assert_eq!(service_detail(&s), None);
        s.info = Some("protocol 2.0".into());
        s.os_hint = Some("Ubuntu Linux".into());
        s.cpes = vec!["cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*".into()];
        assert_eq!(
            service_detail(&s).as_deref(),
            Some("└ protocol 2.0 · os: Ubuntu Linux · cpe:2.3:a:openbsd:openssh:8.9:p1")
        );
    }
}
