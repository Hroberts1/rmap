//! Application state and input handling.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use rmap_core::{HostState, PortList, PortResult, ScanEvent, Timing, parse_targets};
use rmap_engine::{Scan, ScanConfig};
use tokio::runtime::Handle;

/// Most engine events handled per frame, so a burst can't stall input.
const EVENTS_PER_FRAME: usize = 5_000;
const MAX_LOG_LINES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Targets,
    Ports,
    Timing,
    Discovery,
}

impl Field {
    const ALL: [Field; 4] = [
        Field::Targets,
        Field::Ports,
        Field::Timing,
        Field::Discovery,
    ];

    fn step(self, forward: bool) -> Field {
        let i = Field::ALL.iter().position(|f| *f == self).unwrap_or(0);
        let n = Field::ALL.len();
        Field::ALL[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }]
    }
}

pub struct Form {
    pub targets: String,
    pub ports: String,
    pub timing: u8,
    pub discovery: bool,
    pub focus: Field,
    pub error: Option<String>,
}

impl Default for Form {
    fn default() -> Self {
        Form {
            targets: String::new(),
            ports: "common".into(),
            timing: 3,
            discovery: true,
            focus: Field::Targets,
            error: None,
        }
    }
}

pub struct HostRow {
    pub hostname: Option<String>,
    pub state: HostState,
    pub rtt: Option<Duration>,
    pub open: Vec<PortResult>,
    pub closed: u32,
    pub filtered: u32,
    pub done: bool,
}

pub struct ScanView {
    pub scan: Scan,
    pub summary: String,
    pub hosts: BTreeMap<IpAddr, HostRow>,
    pub total_hosts: u64,
    pub selected: Option<IpAddr>,
    pub show_down: bool,
    pub started: Instant,
    pub finished: Option<Duration>,
    pub stopped: bool,
    pub log: Vec<String>,
}

impl ScanView {
    pub fn is_running(&self) -> bool {
        self.finished.is_none() && !self.stopped
    }

    pub fn elapsed(&self) -> Duration {
        self.finished.unwrap_or_else(|| self.started.elapsed())
    }

    /// Hosts shown in the list, in address order.
    pub fn visible(&self) -> Vec<IpAddr> {
        self.hosts
            .iter()
            .filter(|(_, h)| self.show_down || h.state != HostState::Down)
            .map(|(ip, _)| *ip)
            .collect()
    }

    pub fn count(&self, state: HostState) -> usize {
        self.hosts.values().filter(|h| h.state == state).count()
    }

    fn move_selection(&mut self, delta: isize) {
        let visible = self.visible();
        if visible.is_empty() {
            return;
        }
        let current = self
            .selected
            .and_then(|s| visible.iter().position(|ip| *ip == s));
        let next = match current {
            Some(i) => (i as isize + delta).clamp(0, visible.len() as isize - 1) as usize,
            None => 0,
        };
        self.selected = Some(visible[next]);
    }

    fn log(&mut self, line: String) {
        self.log.push(line);
        if self.log.len() > MAX_LOG_LINES {
            self.log.remove(0);
        }
    }

    fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { hosts, .. } => self.total_hosts = hosts,
            ScanEvent::Host {
                ip,
                hostname,
                state,
                rtt,
            } => {
                self.hosts.insert(
                    ip,
                    HostRow {
                        hostname,
                        state,
                        rtt,
                        open: Vec::new(),
                        closed: 0,
                        filtered: 0,
                        done: state == HostState::Down,
                    },
                );
                if self.selected.is_none() && state != HostState::Down {
                    self.selected = Some(ip);
                }
            }
            ScanEvent::Port { ip, result } => {
                if let Some(host) = self.hosts.get_mut(&ip) {
                    let at = host.open.partition_point(|p| p.port < result.port);
                    host.open.insert(at, result);
                }
            }
            ScanEvent::HostDone {
                ip,
                closed,
                filtered,
                ..
            } => {
                if let Some(host) = self.hosts.get_mut(&ip) {
                    host.closed = closed;
                    host.filtered = filtered;
                    host.done = true;
                }
            }
            ScanEvent::Warning(msg) => self.log(msg),
            ScanEvent::Finished { elapsed } => {
                self.finished = Some(elapsed);
                let up = self.count(HostState::Up) + self.count(HostState::Assumed);
                self.log(format!(
                    "scan finished: {up} of {} hosts up in {:.1}s",
                    self.total_hosts,
                    elapsed.as_secs_f64()
                ));
            }
        }
    }
}

pub enum Screen {
    Setup,
    Results,
}

pub struct App {
    rt: Handle,
    pub screen: Screen,
    pub form: Form,
    pub scan: Option<ScanView>,
    /// A scan waiting on the user to confirm it may touch public addresses.
    pub pending: Option<(ScanConfig, Vec<String>)>,
    quit: bool,
}

impl App {
    pub fn new(rt: Handle) -> Self {
        App {
            rt,
            screen: Screen::Setup,
            form: Form::default(),
            scan: None,
            pending: None,
            quit: false,
        }
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Pull whatever the engine has produced since the last frame.
    pub fn drain_events(&mut self) {
        let Some(view) = self.scan.as_mut() else {
            return;
        };
        for _ in 0..EVENTS_PER_FRAME {
            match view.scan.events.try_recv() {
                Ok(event) => view.apply(event),
                Err(_) => break,
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.pending.is_some() {
            self.on_confirm_key(key);
            return;
        }
        match self.screen {
            Screen::Setup => self.on_setup_key(key),
            Screen::Results => self.on_results_key(key),
        }
    }

    fn on_confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some((config, _)) = self.pending.take() {
                    self.launch(config);
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.pending = None,
            _ => {}
        }
    }

    fn on_setup_key(&mut self, key: KeyEvent) {
        let form = &mut self.form;
        match key.code {
            KeyCode::Esc => self.quit = true,
            KeyCode::Enter => self.submit(),
            KeyCode::Tab | KeyCode::Down => form.focus = form.focus.step(true),
            KeyCode::BackTab | KeyCode::Up => form.focus = form.focus.step(false),
            code => match form.focus {
                Field::Targets | Field::Ports => {
                    let text = if form.focus == Field::Targets {
                        &mut form.targets
                    } else {
                        &mut form.ports
                    };
                    match code {
                        KeyCode::Char(c) => text.push(c),
                        KeyCode::Backspace => {
                            text.pop();
                        }
                        _ => {}
                    }
                }
                Field::Timing => match code {
                    KeyCode::Left | KeyCode::Char('-') => {
                        form.timing = form.timing.saturating_sub(1)
                    }
                    KeyCode::Right | KeyCode::Char('+') => form.timing = (form.timing + 1).min(5),
                    KeyCode::Char(c @ '0'..='5') => form.timing = c as u8 - b'0',
                    _ => {}
                },
                Field::Discovery => {
                    if matches!(code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) {
                        form.discovery = !form.discovery;
                    }
                }
            },
        }
    }

    fn on_results_key(&mut self, key: KeyEvent) {
        let Some(view) = self.scan.as_mut() else {
            self.screen = Screen::Setup;
            return;
        };
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('n') | KeyCode::Esc => {
                view.scan.stop();
                self.screen = Screen::Setup;
            }
            KeyCode::Char('s') if view.is_running() => {
                view.scan.stop();
                view.stopped = true;
                view.log("scan stopped".into());
            }
            KeyCode::Char('d') => view.show_down = !view.show_down,
            KeyCode::Down | KeyCode::Char('j') => view.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => view.move_selection(-1),
            KeyCode::PageDown => view.move_selection(10),
            KeyCode::PageUp => view.move_selection(-10),
            KeyCode::Home | KeyCode::Char('g') => view.move_selection(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => view.move_selection(isize::MAX / 2),
            _ => {}
        }
    }

    fn submit(&mut self) {
        let form = &mut self.form;
        let targets = match parse_targets(&form.targets) {
            Ok(t) => t,
            Err(e) => {
                form.error = Some(format!("Targets: {e}"));
                form.focus = Field::Targets;
                return;
            }
        };
        let ports = match PortList::parse(&form.ports) {
            Ok(p) => p,
            Err(e) => {
                form.error = Some(format!("Ports: {e}"));
                form.focus = Field::Ports;
                return;
            }
        };
        form.error = None;
        let public: Vec<String> = targets
            .iter()
            .filter(|t| t.may_be_public())
            .map(ToString::to_string)
            .collect();
        let config = ScanConfig {
            targets,
            ports,
            timing: Timing::template(form.timing),
            discovery: form.discovery,
        };
        if public.is_empty() {
            self.launch(config);
        } else {
            self.pending = Some((config, public));
        }
    }

    fn launch(&mut self, config: ScanConfig) {
        let summary = format!(
            "{} · {} port{} · T{} {}{}",
            self.form.targets.trim(),
            config.ports.len(),
            if config.ports.len() == 1 { "" } else { "s" },
            config.timing.level,
            config.timing.name,
            if config.discovery {
                ""
            } else {
                " · no discovery"
            },
        );
        let scan = Scan::start(&self.rt, config);
        self.scan = Some(ScanView {
            scan,
            summary,
            hosts: BTreeMap::new(),
            total_hosts: 0,
            selected: None,
            show_down: false,
            started: Instant::now(),
            finished: None,
            stopped: false,
            log: Vec::new(),
        });
        self.screen = Screen::Results;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::KeyEvent;

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

    #[test]
    fn bad_input_shows_an_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        for c in "10.0.0.999".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Setup));
        let setup = render(&mut app, 80, 24);
        assert!(setup.contains("Targets: 10.0.0.999"));
    }

    #[test]
    fn public_targets_need_confirmation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.form.targets = "8.8.8.8".into();
        press(&mut app, KeyCode::Enter);
        assert!(app.pending.is_some());
        assert!(render(&mut app, 80, 24).contains("public addresses"));
        press(&mut app, KeyCode::Char('n'));
        assert!(app.pending.is_none() && app.scan.is_none());
    }

    #[test]
    fn scans_localhost_and_renders_results() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        rt.spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let mut app = App::new(rt.handle().clone());
        app.form.targets = "127.0.0.1".into();
        app.form.ports = port.to_string();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Results));

        let deadline = Instant::now() + Duration::from_secs(10);
        while app.scan.as_ref().unwrap().finished.is_none() {
            assert!(Instant::now() < deadline, "scan did not finish");
            app.drain_events();
            std::thread::sleep(Duration::from_millis(10));
        }
        let screen = render(&mut app, 110, 30);
        assert!(screen.contains("127.0.0.1"), "{screen}");
        assert!(screen.contains(&format!("{port}/tcp")), "{screen}");
        assert!(screen.contains("done"), "{screen}");

        // Tiny terminals must not panic.
        render(&mut app, 20, 6);
        press(&mut app, KeyCode::Char('n'));
        render(&mut app, 20, 6);
    }
}
