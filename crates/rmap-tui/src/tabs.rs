//! Results-screen tabs: `1` Hosts (the per-host view in ui.rs), `2` Services
//! (open ports grouped across hosts: "which hosts have 445 open?") and `3`
//! Vulns (every finding in the scan, grouped by product and version,
//! worst first). Rows are rebuilt from
//! `ScanView::hosts` each frame, so both tabs fill in live.
//!
//! shortcut: rebuilding every frame is O(open ports), fine for the /24-sized
//! scans this targets; cache the rows on event arrival if a /16 with many
//! open ports ever makes these tabs sluggish.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};
use rmap_core::{PortResult, Protocol, VulnCheck, VulnTier, Vulnerability, service_name};

use crate::app::{HostRow, ScanView};
use crate::ui::{ACCENT, STACK_BELOW, centered, ellipsize, highlight, pane_block, vuln_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Hosts,
    Services,
    Vulns,
}

type GroupKey = (u16, Protocol, String);
type FindingKey = (IpAddr, u16, Protocol, String);

/// A Vulns-tab row: a product group (by its key) or one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VulnKey {
    Group(String),
    Finding(FindingKey),
}

/// Selection and scroll state for the Services and Vulns tabs. Rows are
/// remembered by key, not index, so rows arriving mid-scan don't move it.
#[derive(Default)]
pub struct Tabs {
    pub tab: Tab,
    group: Option<GroupKey>,
    group_offset: usize,
    /// Arrow keys move through the selected group's hosts, not the groups.
    in_hosts: bool,
    host: usize,
    host_offset: usize,
    finding: Option<VulnKey>,
    finding_offset: usize,
    /// Vulns groups the user opened or closed, against their default.
    toggled: HashSet<String>,
}

/// One port/protocol and service name, with every host that has it open.
pub struct ServiceGroup<'a> {
    pub port: u16,
    pub protocol: Protocol,
    pub name: String,
    /// In address order.
    pub hosts: Vec<(IpAddr, &'a HostRow, &'a PortResult)>,
}

impl ServiceGroup<'_> {
    fn key(&self) -> GroupKey {
        (self.port, self.protocol, self.name.clone())
    }
}

pub struct Finding<'a> {
    pub ip: IpAddr,
    pub port: &'a PortResult,
    pub vuln: &'a Vulnerability,
    pub tier: VulnTier,
}

impl Finding<'_> {
    fn key(&self) -> FindingKey {
        (
            self.ip,
            self.port.port,
            self.port.protocol,
            self.vuln.id.clone(),
        )
    }
}

/// Open ports grouped by port, protocol and service name, in port order.
pub fn service_groups(hosts: &BTreeMap<IpAddr, HostRow>) -> Vec<ServiceGroup<'_>> {
    let mut groups: BTreeMap<GroupKey, Vec<_>> = BTreeMap::new();
    for (ip, host) in hosts {
        for p in &host.open {
            groups
                .entry((p.port, p.protocol, service_label(p)))
                .or_default()
                .push((*ip, host, p));
        }
    }
    groups
        .into_iter()
        .map(|((port, protocol, name), hosts)| ServiceGroup {
            port,
            protocol,
            name,
            hosts,
        })
        .collect()
}

/// Every match on one product and version (and distro build).
pub struct VulnGroup<'a> {
    /// `OpenSSH 10.2p1`, or the service name when there's no version.
    pub label: String,
    /// Set when the ports are distro builds (`CheckedUpstreamOnly`).
    pub distro: Option<&'a str>,
    /// Counted tiers first, then worst first (see [`worse_first`]).
    pub findings: Vec<Finding<'a>>,
}

impl VulnGroup<'_> {
    fn key(&self) -> String {
        match self.distro {
            Some(d) => format!("{} ({d} build)", self.label),
            None => self.label.clone(),
        }
    }

    pub fn count(&self, tier: VulnTier) -> usize {
        self.findings.iter().filter(|f| f.tier == tier).count()
    }

    /// Open unless all it holds is folded by default: upstream-only,
    /// conditional and client-only matches.
    fn open_by_default(&self) -> bool {
        self.count(VulnTier::Potential) > 0
    }

    /// See [`rmap_report::group_line`].
    pub fn summary(&self) -> String {
        let ports: HashSet<_> = self
            .findings
            .iter()
            .map(|f| (f.ip, f.port.port, f.port.protocol))
            .collect();
        rmap_report::group_line(
            &self.label,
            self.distro,
            self.findings.iter().map(|f| f.tier),
            ports.len(),
        )
    }
}

/// Counted tiers before conditional and client-only; then actively
/// exploited (CISA KEV, where the tier allows the marker), severity, and
/// score, unscored last.
fn worse_first(a: &Finding, b: &Finding) -> std::cmp::Ordering {
    let score = |f: &Finding| f.vuln.score.unwrap_or(-1.0);
    let exploited = |f: &Finding| f.tier.shows_kev() && f.vuln.kev_added.is_some();
    a.tier
        .cmp(&b.tier)
        .then(exploited(b).cmp(&exploited(a)))
        .then(b.vuln.severity.cmp(&a.vuln.severity))
        .then(score(b).total_cmp(&score(a)))
}

/// Every match in the scan, grouped by product and version, worst group
/// first (by its worst finding). Ties keep address and port order.
pub fn vuln_groups(hosts: &BTreeMap<IpAddr, HostRow>) -> Vec<VulnGroup<'_>> {
    let mut groups: Vec<VulnGroup> = Vec::new();
    for (ip, h) in hosts {
        for port in h.open.iter().filter(|p| !p.vulnerabilities.is_empty()) {
            let label = port
                .service
                .as_ref()
                .and_then(|s| s.version_label())
                .unwrap_or_else(|| service_label(port));
            let distro = match &port.vuln_check {
                Some(VulnCheck::CheckedUpstreamOnly { distro, .. }) => Some(distro.as_str()),
                _ => None,
            };
            let i = match groups
                .iter()
                .position(|g| g.label == label && g.distro == distro)
            {
                Some(i) => i,
                None => {
                    groups.push(VulnGroup {
                        label,
                        distro,
                        findings: Vec::new(),
                    });
                    groups.len() - 1
                }
            };
            groups[i]
                .findings
                .extend(port.vulnerabilities.iter().map(|vuln| Finding {
                    ip: *ip,
                    port,
                    vuln,
                    tier: port.vuln_tier(vuln),
                }));
        }
    }
    for g in &mut groups {
        g.findings.sort_by(worse_first);
    }
    groups.sort_by(|a, b| worse_first(&a.findings[0], &b.findings[0]));
    groups
}

/// One drawn Vulns row.
enum VulnRow<'a> {
    Group(&'a VulnGroup<'a>, bool),
    Finding(&'a Finding<'a>),
}

impl VulnRow<'_> {
    fn key(&self) -> VulnKey {
        match self {
            VulnRow::Group(g, _) => VulnKey::Group(g.key()),
            VulnRow::Finding(f) => VulnKey::Finding(f.key()),
        }
    }
}

/// Each group's line, then its findings when open. Client-only matches
/// stay folded into the group's line: they can't be reached on a
/// listening port.
fn vuln_rows<'a>(groups: &'a [VulnGroup<'a>], toggled: &HashSet<String>) -> Vec<VulnRow<'a>> {
    let mut rows = Vec::new();
    for g in groups {
        let open = g.open_by_default() != toggled.contains(&g.key());
        rows.push(VulnRow::Group(g, open));
        if open {
            rows.extend(
                g.findings
                    .iter()
                    .filter(|f| f.tier != VulnTier::ClientOnly)
                    .map(VulnRow::Finding),
            );
        }
    }
    rows
}

/// Service name for display; guesses from the port number end in `?`.
pub(crate) fn service_label(p: &PortResult) -> String {
    match &p.service {
        Some(s) => s.display_name(),
        None => service_name(p.port).map_or_else(|| "unknown".into(), |n| format!("{n}?")),
    }
}

/// Results-screen keys the tabs own. Returns false for keys the caller
/// should handle (quit, export, the Hosts tab's own navigation, ...).
pub fn on_key(view: &mut ScanView, code: KeyCode) -> bool {
    let tab = match code {
        KeyCode::Char('1') => Some(Tab::Hosts),
        KeyCode::Char('2') => Some(Tab::Services),
        KeyCode::Char('3') => Some(Tab::Vulns),
        _ => None,
    };
    if let Some(tab) = tab {
        view.tabs.tab = tab;
        return true;
    }
    let pane_key = matches!(
        code,
        KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Char('h')
            | KeyCode::Char('l')
    );
    let tabs = &mut view.tabs;
    match tabs.tab {
        Tab::Hosts => false,
        Tab::Services if pane_key => {
            tabs.in_hosts = match code {
                KeyCode::Right | KeyCode::Char('l') => true,
                KeyCode::Left | KeyCode::Char('h') => false,
                _ => !tabs.in_hosts,
            };
            true
        }
        Tab::Services => {
            let Some(delta) = nav_delta(code) else {
                return false;
            };
            let groups = service_groups(&view.hosts);
            if tabs.in_hosts {
                let n = groups
                    .iter()
                    .find(|g| Some(g.key()) == tabs.group)
                    .map_or(0, |g| g.hosts.len());
                tabs.host = step_index(tabs.host, n, delta);
            } else {
                let keys: Vec<GroupKey> = groups.iter().map(ServiceGroup::key).collect();
                let next = step(&keys, tabs.group.as_ref(), delta);
                if next != tabs.group {
                    tabs.host = 0;
                    tabs.host_offset = 0;
                }
                tabs.group = next;
            }
            true
        }
        // One pane: there is nothing for Tab or ←→ to switch to.
        Tab::Vulns if pane_key => true,
        Tab::Vulns => {
            let groups = vuln_groups(&view.hosts);
            let rows = vuln_rows(&groups, &tabs.toggled);
            if matches!(code, KeyCode::Enter | KeyCode::Char(' ')) {
                // Open or close the selected row's group, and select it.
                let i = resolve(rows.iter().map(VulnRow::key), tabs.finding.as_ref());
                let group = match rows.get(i) {
                    Some(VulnRow::Group(g, _)) => g.key(),
                    Some(VulnRow::Finding(f)) => groups
                        .iter()
                        .find(|g| g.findings.iter().any(|x| x.key() == f.key()))
                        .map_or_else(String::new, VulnGroup::key),
                    None => return true,
                };
                if !tabs.toggled.remove(&group) {
                    tabs.toggled.insert(group.clone());
                }
                tabs.finding = Some(VulnKey::Group(group));
                return true;
            }
            let Some(delta) = nav_delta(code) else {
                return false;
            };
            let keys: Vec<VulnKey> = rows.iter().map(VulnRow::key).collect();
            tabs.finding = step(&keys, tabs.finding.as_ref(), delta);
            true
        }
    }
}

fn nav_delta(code: KeyCode) -> Option<isize> {
    Some(match code {
        KeyCode::Down | KeyCode::Char('j') => 1,
        KeyCode::Up | KeyCode::Char('k') => -1,
        KeyCode::PageDown => 10,
        KeyCode::PageUp => -10,
        KeyCode::Home | KeyCode::Char('g') => isize::MIN,
        KeyCode::End | KeyCode::Char('G') => isize::MAX,
        _ => return None,
    })
}

fn step_index(i: usize, n: usize, delta: isize) -> usize {
    if n == 0 {
        return 0;
    }
    (i as isize).saturating_add(delta).clamp(0, n as isize - 1) as usize
}

/// The key `delta` rows from `current`; an unknown or missing `current`
/// counts as the first row, which is what the renderer shows selected.
fn step<K: PartialEq + Clone>(keys: &[K], current: Option<&K>, delta: isize) -> Option<K> {
    let i = current
        .and_then(|c| keys.iter().position(|k| k == c))
        .unwrap_or(0);
    keys.get(step_index(i, keys.len(), delta)).cloned()
}

/// Index of `current` in `keys`, else the first row.
fn resolve<K: PartialEq>(mut keys: impl Iterator<Item = K>, current: Option<&K>) -> usize {
    current
        .and_then(|c| keys.position(|k| &k == c))
        .unwrap_or(0)
}

/// The tab strip under the header: ` [1 Hosts]  2 Services   3 Vulns `.
pub fn draw_strip(frame: &mut Frame, area: Rect, view: &ScanView) {
    let mut spans = vec![Span::raw(" ")];
    for (tab, label) in [
        (Tab::Hosts, "1 Hosts"),
        (Tab::Services, "2 Services"),
        (Tab::Vulns, "3 Vulns"),
    ] {
        spans.push(if view.tabs.tab == tab {
            Span::raw(format!("[{label}]")).bold().fg(ACCENT)
        } else {
            Span::raw(format!(" {label} ")).dim()
        });
        spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Draw the current tab into `area`. Returns false on the Hosts tab, which
/// ui.rs draws itself.
pub fn draw(frame: &mut Frame, area: Rect, view: &mut ScanView) -> bool {
    match view.tabs.tab {
        Tab::Hosts => return false,
        Tab::Services => draw_services(frame, area, view),
        Tab::Vulns => draw_vulns(frame, area, view),
    }
    true
}

fn empty_message(frame: &mut Frame, area: Rect, msg: &str) {
    let width = (msg.chars().count() as u16).min(area.width.saturating_sub(2));
    frame.render_widget(Paragraph::new(msg).dim(), centered(area, width, 1));
}

fn draw_services(frame: &mut Frame, area: Rect, view: &mut ScanView) {
    let running = view.is_running();
    let ScanView { hosts, tabs, .. } = view;
    let groups = service_groups(hosts);

    let [list, detail] = if area.width < STACK_BELOW {
        let max = (area.height / 2).max(3);
        let want = groups.len() as u16 + 3;
        Layout::vertical([Constraint::Length(want.clamp(3, max)), Constraint::Min(0)]).areas(area)
    } else {
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area)
    };

    let block = pane_block(format!(" services ({}) ", groups.len()), !tabs.in_hosts);
    if groups.is_empty() {
        frame.render_widget(block, list);
        empty_message(
            frame,
            list,
            if running {
                "waiting for open ports…"
            } else {
                "no open ports"
            },
        );
        frame.render_widget(pane_block(" hosts ", tabs.in_hosts), detail);
        return;
    }
    let sel = resolve(groups.iter().map(ServiceGroup::key), tabs.group.as_ref());
    let group = &groups[sel];
    tabs.group = Some(group.key());

    let rows = groups.iter().map(|g| {
        Row::new([
            Cell::from(format!("{}/{}", g.port, g.protocol.as_str())),
            Cell::from(g.name.clone()),
            Cell::from(g.hosts.len().to_string()).fg(ACCENT),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Fill(1),
            Constraint::Length(5),
        ],
    )
    .header(Row::new(["PORT", "SERVICE", "HOSTS"]).bold().dim())
    .block(block)
    .row_highlight_style(highlight(!tabs.in_hosts))
    .highlight_symbol("▌");
    let mut state = TableState::default()
        .with_offset(tabs.group_offset)
        .with_selected(Some(sel));
    frame.render_stateful_widget(table, list, &mut state);
    tabs.group_offset = state.offset();

    // The selected group's hosts.
    let title = format!(
        "{}/{} · {} · {} host{}",
        group.port,
        group.protocol.as_str(),
        group.name,
        group.hosts.len(),
        if group.hosts.len() == 1 { "" } else { "s" }
    );
    let title = format!(
        " {} ",
        ellipsize(&title, detail.width.saturating_sub(4) as usize)
    );
    let addr_w = group
        .hosts
        .iter()
        .map(|(ip, _, _)| ip.to_string().len())
        .max()
        .unwrap_or(0)
        .max("ADDRESS".len());
    let name_w = group
        .hosts
        .iter()
        .filter_map(|(_, h, _)| h.hostname.as_deref())
        .map(|n| n.chars().count())
        .max()
        .unwrap_or(0)
        .clamp("NAME".len(), 24);
    let rows = group.hosts.iter().map(|(ip, h, p)| {
        let version = p
            .service
            .as_ref()
            .and_then(|s| s.version_label())
            .unwrap_or_default();
        let cves = match p.counted_vulns().count() {
            0 => String::new(),
            n => format!("!{n}"),
        };
        Row::new([
            Cell::from(ip.to_string()),
            Cell::from(ellipsize(h.hostname.as_deref().unwrap_or_default(), name_w)).dim(),
            Cell::from(version),
            Cell::from(cves).fg(Color::Red).bold(),
        ])
    });
    tabs.host = tabs.host.min(group.hosts.len() - 1);
    let table = Table::new(
        rows,
        [
            Constraint::Length(addr_w as u16),
            Constraint::Length(name_w as u16),
            Constraint::Fill(1),
            Constraint::Length(4),
        ],
    )
    .header(Row::new(["ADDRESS", "NAME", "VERSION", "CVE"]).bold().dim())
    .block(pane_block(title, tabs.in_hosts))
    .row_highlight_style(highlight(tabs.in_hosts))
    .highlight_symbol("▌");
    let mut state = TableState::default()
        .with_offset(tabs.host_offset)
        .with_selected(Some(tabs.host));
    frame.render_stateful_widget(table, detail, &mut state);
    tabs.host_offset = state.offset();
}

fn draw_vulns(frame: &mut Frame, area: Rect, view: &mut ScanView) {
    let running = view.is_running();
    let [top, area] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    frame.render_widget(
        Paragraph::new(format!(" {}", crate::vuln_status::coverage(view))).dim(),
        top,
    );
    let ScanView { hosts, tabs, .. } = view;
    let groups = vuln_groups(hosts);
    let all = vuln_rows(&groups, &tabs.toggled);
    if all.is_empty() {
        frame.render_widget(pane_block(" potential CVEs ", true), area);
        empty_message(
            frame,
            area,
            if running {
                "no potential CVEs yet"
            } else {
                "no potential CVEs (matching needs Services and Vulns on)"
            },
        );
        return;
    }
    let sel = resolve(all.iter().map(VulnRow::key), tabs.finding.as_ref());
    tabs.finding = Some(all[sel].key());

    // Inside the borders, less the highlight-symbol column.
    let inner = area.width.saturating_sub(3) as usize;
    let places: Vec<String> = all
        .iter()
        .map(|row| match row {
            VulnRow::Finding(f) => {
                let addr = SocketAddr::new(f.ip, f.port.port);
                format!("{addr}/{}", f.port.protocol.as_str())
            }
            VulnRow::Group(..) => String::new(),
        })
        .collect();
    let place_w = places
        .iter()
        .map(|s| s.chars().count())
        .max()
        .unwrap_or(0)
        .min(inner / 3)
        .max(8);
    let text_w = inner.saturating_sub(place_w + 1);
    let rows = all.iter().zip(&places).map(|(row, place)| {
        let f = match row {
            VulnRow::Group(g, open) => {
                let mark = if *open { "▾" } else { "▸" };
                let lines: Vec<Line> = crate::ui::wrap(&g.summary(), inner.saturating_sub(2), 2)
                    .into_iter()
                    .enumerate()
                    .map(|(i, l)| {
                        let lead = if i == 0 { mark } else { " " };
                        Line::from(format!("{lead} {l}")).bold()
                    })
                    .collect();
                let height = lines.len().max(1) as u16;
                return Row::new([Cell::from(Text::from(lines)).column_span(2)]).height(height);
            }
            VulnRow::Finding(f) => f,
        };
        let product = match &f.port.service {
            Some(s) => s.version_label().unwrap_or_else(|| s.display_name()),
            None => service_label(f.port),
        };
        let left = Text::from(vec![
            Line::from(ellipsize(place, place_w)),
            Line::from(ellipsize(&product, place_w)).dim(),
        ]);
        let right = vuln_text(f.vuln, text_w);
        let height = right.lines.len().max(2) as u16;
        Row::new([Cell::from(left), Cell::from(right)]).height(height)
    });
    let title = format!(
        " potential CVEs · {} of {} · Enter opens/closes a group ",
        sel + 1,
        all.len()
    );
    let table = Table::new(
        rows,
        [Constraint::Length(place_w as u16), Constraint::Fill(1)],
    )
    .block(pane_block(
        ellipsize(&title, area.width.saturating_sub(2) as usize),
        true,
    ))
    .row_highlight_style(highlight(true))
    .highlight_symbol("▌");
    let mut state = TableState::default()
        .with_offset(tabs.finding_offset)
        .with_selected(Some(sel));
    frame.render_stateful_widget(table, area, &mut state);
    tabs.finding_offset = state.offset();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, Screen};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
    use rmap_core::{HostState, PortState, ScanEvent, Service, VulnSeverity};

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(w as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect()
    }

    fn view(app: &mut App) -> &mut ScanView {
        app.scan.as_mut().unwrap()
    }

    fn open(view: &mut ScanView, ip: &str, port: u16, name: Option<&str>) {
        let ip: IpAddr = ip.parse().unwrap();
        if !view.hosts.contains_key(&ip) {
            view.apply(ScanEvent::Host {
                ip,
                hostname: Some(format!("host-{ip}")),
                state: HostState::Up,
                rtt: None,
            });
        }
        view.apply(ScanEvent::Port {
            ip,
            result: PortResult::new(port, Protocol::Tcp, PortState::Open, None),
        });
        if let Some(name) = name {
            view.apply(ScanEvent::Service {
                ip,
                protocol: Protocol::Tcp,
                port,
                service: Service {
                    name: name.into(),
                    product: Some("Samba".into()),
                    version: Some("4.15".into()),
                    method: rmap_core::DetectMethod::Probe,
                    ..Default::default()
                },
            });
        }
    }

    fn cve(view: &mut ScanView, ip: &str, port: u16, id: &str, sev: VulnSeverity, score: f32) {
        view.apply(ScanEvent::Vulnerabilities {
            ip: ip.parse().unwrap(),
            protocol: Protocol::Tcp,
            port,
            findings: vec![Vulnerability {
                id: id.into(),
                summary: format!("{id} lets a remote attacker do something bad over the network"),
                severity: sev,
                score: Some(score),
                published: None,
                kev_added: None,
                condition: None,
                client_only: false,
            }],
        });
    }

    /// Three hosts: SMB on two (one detected, one not), SSH and RDP on one,
    /// CVEs of every severity spread across them.
    fn audit_scan() -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.store = None;
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Results));
        let v = view(&mut app);
        v.scan.stop();
        v.stopped = true;
        open(v, "10.0.0.5", 445, Some("microsoft-ds"));
        open(v, "10.0.0.2", 445, Some("microsoft-ds"));
        open(v, "10.0.0.2", 22, None);
        open(v, "10.0.0.9", 3389, None);
        open(v, "10.0.0.9", 445, None);
        cve(
            v,
            "10.0.0.2",
            22,
            "CVE-2023-48795",
            VulnSeverity::Medium,
            5.9,
        );
        cve(v, "10.0.0.5", 445, "CVE-2017-0144", VulnSeverity::High, 8.8);
        cve(
            v,
            "10.0.0.9",
            3389,
            "CVE-2019-0708",
            VulnSeverity::Critical,
            9.8,
        );
        cve(v, "10.0.0.2", 445, "CVE-2022-0001", VulnSeverity::Low, 2.0);
        (rt, app)
    }

    #[test]
    fn services_group_hosts_by_port_and_name() {
        let (_rt, mut app) = audit_scan();
        let groups = service_groups(&view(&mut app).hosts);
        let summary: Vec<(u16, &str, Vec<String>)> = groups
            .iter()
            .map(|g| {
                let ips = g.hosts.iter().map(|(ip, _, _)| ip.to_string()).collect();
                (g.port, g.name.as_str(), ips)
            })
            .collect();
        let ips = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                (22, "ssh?", ips(&["10.0.0.2"])),
                (445, "microsoft-ds", ips(&["10.0.0.2", "10.0.0.5"])),
                // Same port without detection: its well-known name, so a
                // separate group.
                (445, "smb?", ips(&["10.0.0.9"])),
                (3389, "rdp?", ips(&["10.0.0.9"])),
            ]
        );
    }

    #[test]
    fn findings_are_grouped_by_product_worst_group_first() {
        let (_rt, mut app) = audit_scan();
        let groups = vuln_groups(&view(&mut app).hosts);
        let got: Vec<(&str, Vec<&str>)> = groups
            .iter()
            .map(|g| {
                let ids = g.findings.iter().map(|f| f.vuln.id.as_str()).collect();
                (g.label.as_str(), ids)
            })
            .collect();
        assert_eq!(
            got,
            [
                ("rdp?", vec!["CVE-2019-0708"]),
                // Both Samba 4.15 ports in one group, worst first.
                ("Samba 4.15", vec!["CVE-2017-0144", "CVE-2022-0001"]),
                ("ssh?", vec!["CVE-2023-48795"]),
            ]
        );
        assert_eq!(groups[1].summary(), "Samba 4.15: 2 potential · 2 ports");
    }

    /// The field review's OpenSSH ports: an Ubuntu build with a conditional
    /// KEV-listed CVE, a client-only one and a plain one.
    #[test]
    fn distro_conditional_and_client_only_matches_fold_away() {
        let (_rt, mut app) = audit_scan();
        let v = view(&mut app);
        let ip: IpAddr = "10.0.0.20".parse().unwrap();
        v.apply(ScanEvent::Host {
            ip,
            hostname: None,
            state: HostState::Up,
            rtt: None,
        });
        v.apply(ScanEvent::Port {
            ip,
            result: PortResult::new(22, Protocol::Tcp, PortState::Open, None),
        });
        v.apply(ScanEvent::Service {
            ip,
            protocol: Protocol::Tcp,
            port: 22,
            service: Service {
                name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: Some("10.2p1".into()),
                info: Some("protocol 2.0; Ubuntu-2ubuntu3.5".into()),
                ..Default::default()
            },
        });
        let mk = |id: &str, kev: bool, condition: Option<&str>, client_only| Vulnerability {
            id: id.into(),
            summary: format!("{id} summary"),
            severity: VulnSeverity::High,
            score: Some(8.1),
            published: None,
            kev_added: kev.then(|| "2026-11-01".into()),
            condition: condition.map(Into::into),
            client_only,
        };
        v.apply(ScanEvent::Vulnerabilities {
            ip,
            protocol: Protocol::Tcp,
            port: 22,
            findings: vec![
                mk("CVE-2026-123158", true, Some("musl-libc:musl"), false),
                mk("CVE-2026-60002", false, None, true),
                mk("CVE-2026-106553", false, None, false),
            ],
        });
        v.apply(ScanEvent::VulnCheck {
            ip,
            protocol: Protocol::Tcp,
            port: 22,
            status: VulnCheck::CheckedUpstreamOnly {
                product: "OpenSSH".into(),
                version: "10.2p1".into(),
                matches: 1,
                distro: "Ubuntu".into(),
            },
        });
        let groups = vuln_groups(&v.hosts);
        let ssh = groups.last().unwrap();
        assert_eq!(
            ssh.summary(),
            "OpenSSH 10.2p1: 1 potential (upstream match; Ubuntu build) · 1 conditional \
             (platform not verified) · 1 client-only, not counted · 1 port"
        );
        assert_eq!(v.tabs.toggled.len(), 0);

        press(&mut app, KeyCode::Char('3'));
        let screen = render(&mut app, 140, 40);
        assert!(
            screen.contains("CVE coverage: 1 of 6 open ports checked"),
            "{screen}"
        );
        assert!(screen.contains("▸ OpenSSH 10.2p1: 1 potential"), "{screen}");
        assert!(!screen.contains("CVE-2026-106553"), "collapsed:\n{screen}");

        press(&mut app, KeyCode::End); // the OpenSSH group
        press(&mut app, KeyCode::Enter);
        let screen = render(&mut app, 140, 40);
        assert!(screen.contains("▾ OpenSSH 10.2p1"), "{screen}");
        assert!(screen.contains("CVE-2026-106553"), "{screen}");
        assert!(
            screen.contains("conditional: only with musl-libc:musl"),
            "{screen}"
        );
        assert!(!screen.contains("actively exploited"), "{screen}");
        assert!(!screen.contains("CVE-2026-60002"), "client-only:\n{screen}");
        press(&mut app, KeyCode::Enter);
        assert!(!render(&mut app, 140, 40).contains("CVE-2026-106553"));
    }

    #[test]
    fn services_tab_renders_at_80_and_120_columns() {
        let (_rt, mut app) = audit_scan();
        press(&mut app, KeyCode::Char('2'));
        press(&mut app, KeyCode::Down); // 445/tcp microsoft-ds
        for (w, h) in [(120, 32), (80, 24)] {
            let screen = render(&mut app, w, h);
            for needle in [
                "[2 Services]",
                "1 Hosts",
                "3389/tcp",
                "rdp",
                "445/tcp · microsoft-ds · 2 hosts",
                "10.0.0.5",
                "host-10.0.0.5",
                "Samba 4.15",
                "!1",
            ] {
                assert!(screen.contains(needle), "{needle} at {w}x{h}:\n{screen}");
            }
            if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
                println!("{screen}");
            }
        }
    }

    #[test]
    fn vulns_tab_lists_worst_first_with_whole_summaries() {
        let (_rt, mut app) = audit_scan();
        press(&mut app, KeyCode::Char('3'));
        for (w, h) in [(120, 32), (80, 24)] {
            let screen = render(&mut app, w, h);
            for needle in [
                "[3 Vulns]",
                "CVE-2019-0708",
                "10.0.0.9:3389/tcp",
                "over the network", // end of the summary, wrapped
                "1 of 7",
                "▾ rdp?: 1 potential · 1 port",
                "CVE coverage: 0 of 5 open ports checked",
            ] {
                assert!(screen.contains(needle), "{needle} at {w}x{h}:\n{screen}");
            }
            let crit = screen.find("CRIT").expect("CRIT label");
            let high = screen.find("HIGH").expect("HIGH label");
            assert!(crit < high, "worst first:\n{screen}");
            if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
                println!("{screen}");
            }
        }
        press(&mut app, KeyCode::End);
        let screen = render(&mut app, 80, 24);
        assert!(
            screen.contains("CVE-2023-48795") && screen.contains("7 of 7"),
            "{screen}"
        );
        assert!(screen.contains("MED"), "{screen}");
    }

    #[test]
    fn selection_follows_its_row_as_results_arrive() {
        let (_rt, mut app) = audit_scan();
        press(&mut app, KeyCode::Char('2'));
        press(&mut app, KeyCode::End); // 3389/tcp rdp
        render(&mut app, 80, 24);
        // A new lower port shifts every row down by one.
        open(view(&mut app), "10.0.0.7", 21, None);
        let screen = render(&mut app, 80, 24);
        assert!(screen.contains("3389/tcp · rdp? · 1 host"), "{screen}");

        // Tab moves into the group's hosts; ↑↓ then move there.
        press(&mut app, KeyCode::Home); // 21 ftp
        press(&mut app, KeyCode::Down); // 22 ssh
        press(&mut app, KeyCode::Down); // 445 microsoft-ds
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Down);
        let tabs = &view(&mut app).tabs;
        assert!(tabs.in_hosts);
        assert_eq!(
            tabs.group,
            Some((445, Protocol::Tcp, "microsoft-ds".to_string()))
        );
        assert_eq!(tabs.host, 1);
        press(&mut app, KeyCode::Down);
        assert_eq!(view(&mut app).tabs.host, 1, "stops at the last host");
        press(&mut app, KeyCode::Left);
        assert!(!view(&mut app).tabs.in_hosts);
    }

    #[test]
    fn hosts_tab_keys_still_work_and_empty_tabs_do_not_panic() {
        let (_rt, mut app) = audit_scan();
        press(&mut app, KeyCode::Char('3'));
        press(&mut app, KeyCode::Char('1'));
        press(&mut app, KeyCode::Tab);
        assert_eq!(view(&mut app).focus, crate::app::Pane::Ports);
        assert!(render(&mut app, 80, 24).contains("[1 Hosts]"));

        view(&mut app).hosts.clear();
        for (tab, msg) in [('2', "no open ports"), ('3', "no potential CVEs")] {
            press(&mut app, KeyCode::Char(tab));
            press(&mut app, KeyCode::Down);
            let screen = render(&mut app, 100, 24);
            assert!(screen.contains(msg), "{screen}");
        }
        let (_rt, mut app) = audit_scan();
        for tab in ['2', '3'] {
            press(&mut app, KeyCode::Char(tab));
            for (w, h) in [(40, 12), (20, 6), (1, 1)] {
                render(&mut app, w, h);
            }
        }
    }
}
