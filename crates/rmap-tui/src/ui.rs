//! Rendering. Pure functions of `App` state; no side effects beyond the frame.

use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Gauge, Paragraph, Row, Table, TableState, Wrap};
use rmap_core::{HostState, PortState, Service, Timing, service_name};

use crate::app::{App, Field, HostRow, ScanView, Screen};

const ACCENT: Color = Color::Cyan;

pub fn draw(frame: &mut Frame, app: &mut App) {
    match app.screen {
        Screen::Setup => draw_setup(frame, app),
        Screen::Results => {
            if let Some(view) = app.scan.as_ref() {
                draw_results(frame, view);
            }
        }
    }
    if let Some((_, public)) = &app.pending {
        draw_public_warning(frame, public);
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    area
}

fn key_help(pairs: &[(&str, &str)]) -> Line<'static> {
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
        21.min(frame.area().height),
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
        |frame: &mut Frame, area: Rect, field: Field, name, value: &str, placeholder| {
            let shown = if value.is_empty() {
                Span::raw(placeholder).dim().italic()
            } else {
                Span::raw(value.to_string())
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![label(field, name), shown])),
                area,
            );
            if form.focus == field {
                let x = area.x + 13 + value.chars().count() as u16;
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

fn draw_results(frame: &mut Frame, view: &ScanView) {
    let log_height = if view.log.is_empty() { 0 } else { 5 };
    let [header, body, log, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(5),
        Constraint::Length(log_height),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, header, view);
    let [hosts, detail] =
        Layout::horizontal([Constraint::Percentage(36), Constraint::Percentage(64)]).areas(body);
    draw_host_table(frame, hosts, view);
    draw_host_detail(frame, detail, view);
    if log_height > 0 {
        draw_log(frame, log, view);
    }

    let mut help = vec![("↑↓", "select"), ("d", "toggle down hosts")];
    if view.is_running() {
        help.push(("s", "stop"));
    }
    help.extend([("n", "new scan"), ("q", "quit")]);
    frame.render_widget(Paragraph::new(key_help(&help)), footer);
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
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(format!(" {up} up")).fg(Color::Green).bold(),
            Span::raw(format!(" · {down} down")).dim(),
            Span::raw(format!(
                " · {} of {} hosts seen",
                view.hosts.len(),
                view.total_hosts
            )),
            Span::raw(format!(" · {open} open ports")).fg(ACCENT),
            Span::raw(format!(" · {}", fmt_elapsed(view.elapsed()))),
        ])),
        stats,
    );

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

fn draw_host_table(frame: &mut Frame, area: Rect, view: &ScanView) {
    let visible = view.visible();
    let rows = visible.iter().map(|ip| {
        let h = &view.hosts[ip];
        let (mark, style) = match h.state {
            HostState::Up | HostState::Assumed if !h.open.is_empty() => {
                ("●", Style::new().fg(Color::Green))
            }
            HostState::Up | HostState::Assumed => ("●", Style::new().fg(Color::Yellow)),
            HostState::Down => ("○", Style::new().add_modifier(Modifier::DIM)),
        };
        let open = if h.done || !h.open.is_empty() {
            h.open.len().to_string()
        } else {
            "…".into()
        };
        Row::new(vec![
            Cell::from(mark).style(style),
            Cell::from(ip.to_string()),
            Cell::from(h.hostname.clone().unwrap_or_default()).dim(),
            Cell::from(open).fg(ACCENT),
            Cell::from(h.rtt.map(fmt_rtt).unwrap_or_default()).dim(),
        ])
        .style(if h.state == HostState::Down {
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
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Min(15),
            Constraint::Fill(1),
            Constraint::Length(4),
            Constraint::Length(7),
        ],
    )
    .header(
        Row::new(["", "ADDRESS", "NAME", "OPEN", "RTT"])
            .bold()
            .dim(),
    )
    .block(Block::bordered().title(title))
    .row_highlight_style(
        Style::new()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
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

fn draw_host_detail(frame: &mut Frame, area: Rect, view: &ScanView) {
    let Some((ip, host)) = view
        .selected
        .and_then(|ip| view.hosts.get(&ip).map(|h| (ip, h)))
    else {
        frame.render_widget(Block::bordered().title(" details "), area);
        return;
    };
    let block = Block::bordered()
        .title(format!(" {ip} "))
        .padding(ratatui::widgets::Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [info, ports, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    frame.render_widget(Paragraph::new(host_info(host)), info);

    let rows = host.open.iter().flat_map(|p| {
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
        let main = Row::new(vec![
            Cell::from(format!("{}/{}", p.port, p.protocol.as_str())),
            Cell::from(p.state.as_str()).fg(state_color),
            Cell::from(name),
            Cell::from(version),
            Cell::from(p.rtt.map(fmt_rtt).unwrap_or_default()).dim(),
        ]);
        let detail = p.service.as_ref().and_then(service_detail).map(|d| {
            Row::new(vec![
                Cell::default(),
                Cell::default(),
                Cell::default(),
                Cell::from(d),
            ])
            .dim()
        });
        std::iter::once(main).chain(detail)
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(13),
            Constraint::Length(12),
            Constraint::Fill(1),
            Constraint::Length(7),
        ],
    )
    .header(
        Row::new(["PORT", "STATE", "SERVICE", "VERSION", "RTT"])
            .bold()
            .dim(),
    );
    frame.render_widget(table, ports);

    let not_shown = if host.done {
        format!(
            "not shown: {} closed, {} filtered",
            host.closed, host.filtered
        )
    } else if host.state == HostState::Down {
        String::new()
    } else {
        "scanning…".into()
    };
    frame.render_widget(Paragraph::new(not_shown).dim(), footer);
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

fn host_info(h: &HostRow) -> Vec<Line<'static>> {
    let state = match h.state {
        HostState::Up => Span::raw("up").fg(Color::Green),
        HostState::Assumed => Span::raw("assumed up (discovery off)").fg(Color::Yellow),
        HostState::Down => Span::raw("down (no response)").dim(),
    };
    let mut first = vec![Span::raw("state ").dim(), state];
    if let Some(rtt) = h.rtt {
        first.push(Span::raw(format!("  latency {}", fmt_rtt(rtt))).dim());
    }
    let second = match &h.hostname {
        Some(name) => Line::from(vec![Span::raw("name  ").dim(), Span::raw(name.clone())]),
        None => Line::default(),
    };
    vec![Line::from(first), second]
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
