//! Mouse input. The renderer records where things were drawn in a
//! [`HitMap`] each frame; clicks and wheel events are resolved against it,
//! so input code never recomputes layout.

use std::net::IpAddr;

use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};

use crate::app::{App, Field, Pane, Screen};

/// Hosts moved per wheel notch; ports move one group at a time since a
/// group can be several lines tall.
const HOST_WHEEL_STEP: isize = 3;

/// Where the last frame drew its clickable parts.
#[derive(Debug, Default)]
pub struct HitMap {
    /// Setup form rows.
    pub fields: Vec<(Field, Rect)>,
    pub hosts: Option<ListHit<IpAddr>>,
    /// Port pane; items are indices into the selected host's open ports.
    pub ports: Option<ListHit<usize>>,
    /// Settings screen rows.
    pub settings: Vec<(crate::settings_ui::Row, Rect)>,
    /// The CVE data pop-up's Open Settings and Not now buttons.
    pub vuln_popup: Option<(Rect, Rect)>,
}

/// A scrolled list on screen.
#[derive(Debug)]
pub struct ListHit<T> {
    /// The whole pane, borders included: where the wheel scrolls it.
    pub pane: Rect,
    /// The drawn rows; screen line `rows.y + i` shows `items[i]`.
    pub rows: Rect,
    pub items: Vec<T>,
}

impl<T: Copy> ListHit<T> {
    /// `items` is one entry per screen line, top down, already clipped to
    /// `rows.height`.
    pub fn new(pane: Rect, rows: Rect, mut items: Vec<T>) -> Self {
        items.truncate(rows.height as usize);
        ListHit { pane, rows, items }
    }

    fn at(&self, pos: Position) -> Option<T> {
        if !self.rows.contains(pos) {
            return None;
        }
        self.items.get(usize::from(pos.y - self.rows.y)).copied()
    }
}

impl App {
    pub fn on_mouse(&mut self, ev: MouseEvent) {
        rmap_log::trace!("mouse {:?} at {},{}", ev.kind, ev.column, ev.row);
        let pos = Position::new(ev.column, ev.row);
        // Its buttons answer like their keys; any other click is swallowed.
        if self.vuln_popup.is_some() {
            if ev.kind == MouseEventKind::Down(MouseButton::Left)
                && let Some((open, not_now)) = self.hits.vuln_popup
            {
                if open.contains(pos) {
                    self.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                } else if not_now.contains(pos) {
                    self.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
                }
            }
            return;
        }
        // Overlays are keyboard-only; a stray click must not reach the
        // screen underneath (or answer a y/n prompt).
        if self.confirm.is_some() || self.pending.is_some() || self.help || self.dialog.is_some() {
            return;
        }
        if self.settings.is_open() {
            self.on_settings_mouse(ev.kind, pos);
            return;
        }
        match self.screen {
            Screen::Setup => self.on_setup_mouse(ev.kind, pos),
            Screen::Results => self.on_results_mouse(ev.kind, pos),
            Screen::Diff => {}
        }
    }

    fn on_setup_mouse(&mut self, kind: MouseEventKind, pos: Position) {
        if kind != MouseEventKind::Down(MouseButton::Left) {
            return;
        }
        let Some(&(field, _)) = self.hits.fields.iter().find(|(_, r)| r.contains(pos)) else {
            return;
        };
        self.form.focus = field;
        // Space flips toggles and cycles the scan type; reuse that path so
        // the Services/Vulns coupling stays in one place.
        if matches!(
            field,
            Field::ScanType | Field::Discovery | Field::Names | Field::Services | Field::Vulns
        ) {
            self.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        }
    }

    fn on_results_mouse(&mut self, kind: MouseEventKind, pos: Position) {
        let Some(view) = self.scan.as_mut() else {
            return;
        };
        let hosts = self.hits.hosts.as_ref();
        let ports = self.hits.ports.as_ref();
        let delta = match kind {
            MouseEventKind::ScrollUp => -1,
            MouseEventKind::ScrollDown => 1,
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(ip) = hosts.and_then(|h| h.at(pos)) {
                    if view.selected != Some(ip) {
                        view.port_selected = 0;
                        view.port_offset = 0;
                    }
                    view.selected = Some(ip);
                    view.focus = Pane::Hosts;
                } else if let Some(i) = ports.and_then(|p| p.at(pos)) {
                    view.port_selected = i;
                    view.focus = Pane::Ports;
                }
                return;
            }
            _ => return,
        };
        if hosts.is_some_and(|h| h.pane.contains(pos)) {
            view.move_selection(delta * HOST_WHEEL_STEP);
        } else if ports.is_some_and(|p| p.pane.contains(pos)) {
            view.move_port_selection(delta);
        }
    }

    /// `m`: turn mouse capture off so the terminal's own text selection
    /// works, or back on. The event loop applies it to the terminal.
    pub(crate) fn toggle_mouse_capture(&mut self) {
        self.mouse_capture = !self.mouse_capture;
        rmap_log::info!(
            "mouse capture {}",
            if self.mouse_capture { "on" } else { "off" }
        );
        if let Some(view) = self.scan.as_mut() {
            view.log(if self.mouse_capture {
                "mouse on (m to turn off and select text)".into()
            } else {
                "mouse off: drag to select text, m turns it back on".into()
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use rmap_core::{
        HostState, PortResult, PortState, Protocol, ScanEvent, Service, VulnSeverity, Vulnerability,
    };

    use super::*;
    use crate::app::Confirm;

    fn app() -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.store = None;
        (rt, app)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    /// Draws a frame (which records the hit map) and returns its lines.
    fn render(app: &mut App, w: u16, h: u16) -> Vec<String> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(w.max(1) as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect())
            .collect()
    }

    /// Screen cell (column, row) where `needle` first appears.
    fn find(screen: &[String], needle: &str) -> (u16, u16) {
        for (y, line) in screen.iter().enumerate() {
            if let Some(byte) = line.find(needle) {
                return (line[..byte].chars().count() as u16, y as u16);
            }
        }
        panic!("{needle} not on screen:\n{}", screen.join("\n"));
    }

    fn mouse(app: &mut App, kind: MouseEventKind, (column, row): (u16, u16)) {
        app.on_mouse(MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        });
    }

    fn click(app: &mut App, at: (u16, u16)) {
        mouse(app, MouseEventKind::Down(MouseButton::Left), at);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Results for three up hosts; 10.0.0.2 has five ports, with a detail
    /// line and a long CVE under port 22, so port rows are uneven.
    fn results(app: &mut App) {
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        press(app, KeyCode::Enter);
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        for host in ["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
            view.apply(ScanEvent::Host {
                ip: ip(host),
                hostname: None,
                state: HostState::Up,
                rtt: Some(Duration::from_millis(1)),
            });
        }
        let nas = ip("10.0.0.2");
        for port in [22, 80, 443, 445, 5000] {
            view.apply(ScanEvent::Port {
                ip: nas,
                result: PortResult::new(port, Protocol::Tcp, PortState::Open, None),
            });
        }
        view.apply(ScanEvent::Service {
            ip: nas,
            protocol: Protocol::Tcp,
            port: 22,
            service: Service {
                name: "ssh".into(),
                info: Some("protocol 2.0".into()),
                ..Default::default()
            },
        });
        view.apply(ScanEvent::Vulnerabilities {
            ip: nas,
            protocol: Protocol::Tcp,
            port: 22,
            findings: vec![Vulnerability {
                id: "CVE-2024-6387".into(),
                summary: "regreSSHion: unauthenticated remote code execution in sshd on glibc-based Linux systems".into(),
                severity: VulnSeverity::High,
                score: Some(8.1),
                published: None,
                kev_added: None,
                condition: None,
                client_only: false,
            }],
        });
        view.selected = Some(nas);
    }

    fn view(app: &App) -> &crate::app::ScanView {
        app.scan.as_ref().unwrap()
    }

    #[test]
    fn clicking_a_host_selects_and_focuses_it() {
        for (w, h) in [(80, 24), (120, 32)] {
            let (_rt, mut app) = app();
            results(&mut app);
            app.scan.as_mut().unwrap().focus = Pane::Ports;
            app.scan.as_mut().unwrap().port_selected = 3;
            let screen = render(&mut app, w, h);
            click(&mut app, find(&screen, "10.0.0.3"));
            let v = view(&app);
            assert_eq!(v.selected, Some(ip("10.0.0.3")), "{w}x{h}");
            assert_eq!(v.focus, Pane::Hosts);
            assert_eq!(v.port_selected, 0, "new host starts at its first port");
        }
    }

    #[test]
    fn clicking_a_port_line_selects_its_port() {
        for (w, h) in [(80, 24), (120, 32)] {
            let (_rt, mut app) = app();
            results(&mut app);
            let screen = render(&mut app, w, h);
            click(&mut app, find(&screen, "80/tcp"));
            assert_eq!(
                (view(&app).focus, view(&app).port_selected),
                (Pane::Ports, 1)
            );
            // A CVE line belongs to the port above it.
            let screen = render(&mut app, w, h);
            click(&mut app, find(&screen, "CVE-2024-6387"));
            assert_eq!(view(&app).port_selected, 0, "{w}x{h}");
            // So does its wrapped continuation line.
            click(&mut app, find(&screen, "80/tcp"));
            let screen = render(&mut app, w, h);
            click(&mut app, find(&screen, "glibc-based"));
            assert_eq!(view(&app).port_selected, 0, "{w}x{h}");
        }
    }

    #[test]
    fn clicks_on_borders_headers_and_blank_space_do_nothing() {
        let (_rt, mut app) = app();
        results(&mut app);
        let screen = render(&mut app, 80, 24);
        let (x, y) = find(&screen, "ADDRESS");
        let (px, py) = find(&screen, "PORT");
        let last = screen.len() as u16 - 1;
        for at in [(0, 0), (x, y), (x, y - 1), (0, y + 1), (px, py), (79, last)] {
            click(&mut app, at);
            let v = view(&app);
            assert_eq!(
                (v.selected, v.focus, v.port_selected),
                (Some(ip("10.0.0.2")), Pane::Hosts, 0),
                "click at {at:?}"
            );
        }
    }

    #[test]
    fn wheel_scrolls_the_pane_under_the_pointer() {
        let (_rt, mut app) = app();
        results(&mut app);
        let screen = render(&mut app, 80, 24);
        assert!(!screen.iter().any(|l| l.contains("5000/tcp")));
        let over_ports = find(&screen, "443/tcp");
        for _ in 0..4 {
            mouse(&mut app, MouseEventKind::ScrollDown, over_ports);
        }
        assert_eq!(view(&app).port_selected, 4);
        assert_eq!(
            view(&app).focus,
            Pane::Hosts,
            "the wheel doesn't move focus"
        );
        let screen = render(&mut app, 80, 24);
        assert!(
            screen.iter().any(|l| l.contains("5000/tcp")),
            "scrolled into view"
        );
        assert!(view(&app).port_offset > 0);

        let over_hosts = find(&screen, "10.0.0.1");
        mouse(&mut app, MouseEventKind::ScrollUp, over_hosts);
        assert_eq!(view(&app).selected, Some(ip("10.0.0.1")));
        mouse(&mut app, MouseEventKind::ScrollDown, over_hosts);
        assert_eq!(
            view(&app).selected,
            Some(ip("10.0.0.3")),
            "clamped at the end"
        );
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let (_rt, mut app) = app();
        results(&mut app);
        for (w, h) in [(1, 1), (20, 6), (40, 12)] {
            for y in 0..h {
                for x in 0..w {
                    render(&mut app, w, h);
                    for kind in [
                        MouseEventKind::Down(MouseButton::Left),
                        MouseEventKind::ScrollDown,
                        MouseEventKind::ScrollUp,
                    ] {
                        mouse(&mut app, kind, (x, y));
                    }
                }
            }
            // Events from outside the frame (a resize race) are ignored.
            click(&mut app, (u16::MAX, u16::MAX));
        }
    }

    #[test]
    fn vuln_popup_buttons_are_clickable() {
        let (_rt, mut app) = app();
        app.vuln_popup = Some(false);
        let screen = render(&mut app, 80, 24);
        // A click elsewhere is swallowed.
        click(&mut app, (0, 0));
        assert!(app.vuln_popup.is_some());
        click(&mut app, find(&screen, "Not now"));
        assert!(app.vuln_popup.is_none() && !app.settings.is_open());
        app.vuln_popup = Some(false);
        let screen = render(&mut app, 80, 24);
        click(&mut app, find(&screen, "Open Settings  ")); // the button, not the text
        assert!(app.vuln_popup.is_none() && app.settings.is_open());
    }

    #[test]
    fn setup_clicks_focus_fields_and_flip_toggles() {
        let (_rt, mut app) = app();
        let screen = render(&mut app, 80, 24);
        click(&mut app, find(&screen, "Ports"));
        assert_eq!(app.form.focus, Field::Ports);
        assert!(app.form.discovery);
        click(&mut app, find(&screen, "Discovery"));
        assert_eq!(app.form.focus, Field::Discovery);
        assert!(!app.form.discovery);
        click(&mut app, find(&screen, "[ ] needs Services"));
        assert!(app.form.vuln_matching && app.form.service_detection);
        // Blank space and the border leave the form alone.
        let focus = app.form.focus;
        click(&mut app, (0, 0));
        click(&mut app, find(&screen, "rmap · new scan"));
        assert_eq!(app.form.focus, focus);
        assert!(matches!(app.screen, Screen::Setup));
    }

    #[test]
    fn overlays_swallow_clicks() {
        let (_rt, mut app) = app();
        press(&mut app, KeyCode::Esc);
        let screen = render(&mut app, 80, 24);
        click(&mut app, find(&screen, " y "));
        click(&mut app, find(&screen, " n "));
        assert_eq!(app.confirm, Some(Confirm::Quit));
        assert!(!app.should_quit());
        press(&mut app, KeyCode::Char('n'));

        results(&mut app);
        press(&mut app, KeyCode::Char('?'));
        let screen = render(&mut app, 80, 24);
        let at = find(&screen, "10.0.0.3");
        click(&mut app, at);
        mouse(&mut app, MouseEventKind::ScrollDown, at);
        assert!(app.help);
        assert_eq!(view(&app).selected, Some(ip("10.0.0.2")));
    }

    #[test]
    fn m_toggles_capture_and_is_in_help() {
        let (_rt, mut app) = app();
        results(&mut app);
        assert!(app.mouse_capture);
        press(&mut app, KeyCode::Char('m'));
        assert!(!app.mouse_capture);
        assert!(view(&app).log.back().unwrap().contains("select text"));
        press(&mut app, KeyCode::Char('m'));
        assert!(app.mouse_capture);
        press(&mut app, KeyCode::Char('?'));
        let screen = render(&mut app, 80, 24).join("\n");
        assert!(
            screen.contains("mouse on/off (off = select text)") && screen.contains("Shift-drag"),
            "{screen}"
        );
    }
}
