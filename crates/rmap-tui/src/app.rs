//! Application state and input handling.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use rmap_core::{HostState, PortList, PortResult, ScanEvent, ScanType, Timing, parse_targets};
use rmap_engine::{Scan, ScanConfig};
use tokio::runtime::Handle;
use tokio::sync::mpsc::error::TryRecvError;

/// Most engine events handled per frame, so a burst can't stall input.
const EVENTS_PER_FRAME: usize = 5_000;
const MAX_LOG_LINES: usize = 200;
/// Marks engine warnings in the log panel, which draws them highlighted.
pub const WARNING_PREFIX: &str = "warning: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Targets,
    Ports,
    ScanType,
    Timing,
    Discovery,
    Services,
}

impl Field {
    const ALL: [Field; 6] = [
        Field::Targets,
        Field::Ports,
        Field::ScanType,
        Field::Timing,
        Field::Discovery,
        Field::Services,
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
    pub scan_type: ScanType,
    pub timing: u8,
    pub discovery: bool,
    pub service_detection: bool,
    pub focus: Field,
    pub error: Option<String>,
}

impl Default for Form {
    fn default() -> Self {
        Form {
            targets: String::new(),
            ports: "common".into(),
            scan_type: ScanType::Connect,
            timing: 3,
            discovery: true,
            service_detection: false,
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
    /// The engine went away without finishing, most likely a panic.
    pub failed: bool,
    pub log: Vec<String>,
}

impl ScanView {
    pub fn is_running(&self) -> bool {
        self.finished.is_none() && !self.stopped && !self.failed
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
            ScanEvent::Port { ip, result } => match self.hosts.get_mut(&ip) {
                Some(host) => {
                    let key = (result.port, result.protocol);
                    let at = host.open.partition_point(|p| (p.port, p.protocol) < key);
                    host.open.insert(at, result);
                }
                None => rmap_log::warn!("open port {ip}:{} arrived before its host", result.port),
            },
            ScanEvent::Service {
                ip,
                protocol,
                port,
                service,
            } => {
                let found = self.hosts.get_mut(&ip).and_then(|h| {
                    h.open
                        .iter_mut()
                        .find(|p| p.port == port && p.protocol == protocol)
                });
                match found {
                    Some(p) => p.service = Some(service),
                    None => rmap_log::warn!(
                        "service for {ip} {port}/{} arrived before its port",
                        protocol.as_str()
                    ),
                }
            }
            ScanEvent::HostDone {
                ip,
                closed,
                filtered,
                ..
            } => match self.hosts.get_mut(&ip) {
                Some(host) => {
                    host.closed = closed;
                    host.filtered = filtered;
                    host.done = true;
                }
                None => rmap_log::warn!("completion for {ip} arrived before its host"),
            },
            ScanEvent::Warning(msg) => self.log(format!("{WARNING_PREFIX}{msg}")),
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
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The engine always sends Finished before hanging up, so
                    // hanging up without it means the scan died.
                    if view.finished.is_none() && !view.stopped && !view.failed {
                        view.failed = true;
                        rmap_log::error!("scan engine stopped without finishing");
                        let hint = match rmap_log::log_dir() {
                            Some(dir) => format!("; details in {}", dir.display()),
                            None => String::new(),
                        };
                        view.log(format!("scan engine stopped unexpectedly{hint}"));
                    }
                    break;
                }
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        rmap_log::trace!("key {:?} {:?}", key.code, key.modifiers);
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            rmap_log::info!("quit via ctrl-c");
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
                    rmap_log::info!("user confirmed scanning public addresses");
                    self.launch(config);
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                rmap_log::info!("user declined scanning public addresses");
                self.pending = None;
            }
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
                Field::ScanType => {
                    let i = ScanType::ALL
                        .iter()
                        .position(|t| *t == form.scan_type)
                        .unwrap_or(0);
                    let n = ScanType::ALL.len();
                    match code {
                        KeyCode::Right | KeyCode::Char(' ') => {
                            form.scan_type = ScanType::ALL[(i + 1) % n]
                        }
                        KeyCode::Left => form.scan_type = ScanType::ALL[(i + n - 1) % n],
                        _ => {}
                    }
                }
                Field::Discovery => {
                    if matches!(code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) {
                        form.discovery = !form.discovery;
                    }
                }
                Field::Services => {
                    if matches!(code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) {
                        form.service_detection = !form.service_detection;
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
            KeyCode::Char('q') => {
                rmap_log::info!("quit from results screen");
                self.quit = true;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                if view.is_running() {
                    view.scan.stop();
                    view.stopped = true;
                }
                rmap_log::debug!("back to setup screen");
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
                rmap_log::info!("rejected targets {:?}: {e}", form.targets);
                form.error = Some(format!("Targets: {e}"));
                form.focus = Field::Targets;
                return;
            }
        };
        let ports = match PortList::parse(&form.ports) {
            Ok(p) => p,
            Err(e) => {
                rmap_log::info!("rejected ports {:?}: {e}", form.ports);
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
            scan_type: form.scan_type,
            service_detection: form.service_detection,
        };
        if public.is_empty() {
            self.launch(config);
        } else {
            rmap_log::info!("asking to confirm public targets: {public:?}");
            self.pending = Some((config, public));
        }
    }

    fn launch(&mut self, config: ScanConfig) {
        let summary = format!(
            "{} · {} · {} port{} · T{} {}{}",
            self.form.targets.trim(),
            config.scan_type.label(),
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
            failed: false,
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
    use rmap_core::Protocol;

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

    fn app() -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let app = App::new(rt.handle().clone());
        (rt, app)
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    /// A results view fed synthetic events, without running a real scan.
    fn fake_results(app: &mut App) {
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        press(app, KeyCode::Enter);
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true; // keep the disconnect from counting as a failure
        for (ip, state) in [
            ("10.0.0.3", HostState::Up),
            ("10.0.0.1", HostState::Down),
            ("10.0.0.2", HostState::Up),
        ] {
            view.apply(ScanEvent::Host {
                ip: ip.parse().unwrap(),
                hostname: None,
                state,
                rtt: None,
            });
        }
    }

    #[test]
    fn tab_cycles_fields_both_ways() {
        let (_rt, mut app) = app();
        assert_eq!(app.form.focus, Field::Targets);
        for expected in [
            Field::Ports,
            Field::ScanType,
            Field::Timing,
            Field::Discovery,
            Field::Services,
            Field::Targets,
        ] {
            press(&mut app, KeyCode::Tab);
            assert_eq!(app.form.focus, expected);
        }
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.form.focus, Field::Services);
    }

    #[test]
    fn editing_text_fields() {
        let (_rt, mut app) = app();
        type_text(&mut app, "10.0.0.1x");
        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.form.targets, "10.0.0.1");
        press(&mut app, KeyCode::Tab);
        for _ in 0..10 {
            press(&mut app, KeyCode::Backspace); // extra presses on empty text are harmless
        }
        type_text(&mut app, "22");
        assert_eq!(app.form.ports, "22");
    }

    #[test]
    fn timing_clamps_and_accepts_digits() {
        let (_rt, mut app) = app();
        app.form.focus = Field::Timing;
        for _ in 0..10 {
            press(&mut app, KeyCode::Right);
        }
        assert_eq!(app.form.timing, 5);
        for _ in 0..10 {
            press(&mut app, KeyCode::Left);
        }
        assert_eq!(app.form.timing, 0);
        press(&mut app, KeyCode::Char('4'));
        assert_eq!(app.form.timing, 4);
        press(&mut app, KeyCode::Char('9'));
        assert_eq!(app.form.timing, 4, "out-of-range digits are ignored");
    }

    #[test]
    fn discovery_toggles() {
        let (_rt, mut app) = app();
        app.form.focus = Field::Discovery;
        press(&mut app, KeyCode::Char(' '));
        assert!(!app.form.discovery);
        press(&mut app, KeyCode::Right);
        assert!(app.form.discovery);
    }

    #[test]
    fn bad_ports_focus_the_ports_field() {
        let (_rt, mut app) = app();
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "0-10".into();
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.form.focus, Field::Ports);
        assert!(app.form.error.as_deref().unwrap().starts_with("Ports:"));
        app.form.ports = "22".into();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        assert!(app.form.error.is_none(), "error clears on a good submit");
    }

    #[test]
    fn empty_targets_are_rejected() {
        let (_rt, mut app) = app();
        press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Setup));
        assert!(app.form.error.is_some());
    }

    #[test]
    fn confirming_public_targets_starts_the_scan() {
        let (_rt, mut app) = app();
        app.form.targets = "192.0.2.1".into(); // TEST-NET, counted as public
        app.form.ports = "80".into();
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('x'));
        assert!(app.pending.is_some(), "other keys leave the prompt up");
        press(&mut app, KeyCode::Char('y'));
        assert!(app.pending.is_none());
        assert!(matches!(app.screen, Screen::Results));
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let (_rt, mut app) = app();
        app.form.targets = "8.8.8.8".into();
        press(&mut app, KeyCode::Enter);
        assert!(app.pending.is_some());
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit());
    }

    #[test]
    fn esc_quits_setup_but_not_results() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        press(&mut app, KeyCode::Esc);
        assert!(matches!(app.screen, Screen::Setup) && !app.should_quit());
        press(&mut app, KeyCode::Esc);
        assert!(app.should_quit());
    }

    #[test]
    fn host_list_hides_down_hosts_and_navigates() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let selected = |app: &App| app.scan.as_ref().unwrap().selected;
        let view = app.scan.as_ref().unwrap();
        assert_eq!(
            view.visible(),
            [ip("10.0.0.2"), ip("10.0.0.3")],
            "sorted, down host hidden"
        );
        assert_eq!(
            view.selected,
            Some(ip("10.0.0.3")),
            "first up host seen is selected"
        );

        press(&mut app, KeyCode::Up);
        assert_eq!(selected(&app), Some(ip("10.0.0.2")));
        press(&mut app, KeyCode::Up);
        assert_eq!(selected(&app), Some(ip("10.0.0.2")), "stops at the top");
        press(&mut app, KeyCode::End);
        assert_eq!(selected(&app), Some(ip("10.0.0.3")));

        press(&mut app, KeyCode::Char('d'));
        assert_eq!(app.scan.as_ref().unwrap().visible().len(), 3);
        press(&mut app, KeyCode::Home);
        assert_eq!(selected(&app), Some(ip("10.0.0.1")));
        render(&mut app, 100, 30);
    }

    #[test]
    fn open_ports_stay_sorted() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let view = app.scan.as_mut().unwrap();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for port in [443, 22, 8080, 80] {
            view.apply(ScanEvent::Port {
                ip,
                result: PortResult::new(port, Protocol::Tcp, rmap_core::PortState::Open, None),
            });
        }
        let ports: Vec<u16> = view.hosts[&ip].open.iter().map(|p| p.port).collect();
        assert_eq!(ports, [22, 80, 443, 8080]);
    }

    #[test]
    fn service_events_attach_to_their_port() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let view = app.scan.as_mut().unwrap();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let open = rmap_core::PortState::Open;
        view.apply(ScanEvent::Port {
            ip,
            result: PortResult::new(53, Protocol::Tcp, open, None),
        });
        view.apply(ScanEvent::Port {
            ip,
            result: PortResult::new(53, Protocol::Udp, open, None),
        });
        let service = rmap_core::Service {
            name: "domain".into(),
            product: Some("ISC BIND".into()),
            version: Some("9.18".into()),
            ..Default::default()
        };
        view.apply(ScanEvent::Service {
            ip,
            protocol: Protocol::Udp,
            port: 53,
            service,
        });
        let host = &view.hosts[&ip];
        assert_eq!(host.open.len(), 2, "same port number, different protocols");
        assert!(host.open[0].service.is_none(), "tcp/53 untouched");
        assert_eq!(host.open[1].service.as_ref().unwrap().name, "domain");
        app.scan.as_mut().unwrap().selected = Some(ip);
        let screen = render(&mut app, 110, 30);
        assert!(
            screen.contains("53/udp") && screen.contains("ISC BIND 9.18"),
            "{screen}"
        );
    }

    #[test]
    fn scan_type_cycles() {
        let (_rt, mut app) = app();
        app.form.focus = Field::ScanType;
        press(&mut app, KeyCode::Right);
        assert_eq!(app.form.scan_type, ScanType::Syn);
        press(&mut app, KeyCode::Left);
        press(&mut app, KeyCode::Left);
        assert_eq!(app.form.scan_type, ScanType::Udp, "wraps around");
        app.form.focus = Field::Services;
        press(&mut app, KeyCode::Char(' '));
        assert!(app.form.service_detection);
    }

    #[test]
    fn events_for_unknown_hosts_are_ignored() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let view = app.scan.as_mut().unwrap();
        let ghost: IpAddr = "10.9.9.9".parse().unwrap();
        view.apply(ScanEvent::Port {
            ip: ghost,
            result: PortResult::new(1, Protocol::Tcp, rmap_core::PortState::Open, None),
        });
        view.apply(ScanEvent::HostDone {
            ip: ghost,
            closed: 1,
            filtered: 1,
            elapsed: Duration::ZERO,
        });
        assert!(!view.hosts.contains_key(&ghost));
    }

    #[test]
    fn log_panel_is_bounded() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let view = app.scan.as_mut().unwrap();
        for i in 0..MAX_LOG_LINES + 50 {
            view.apply(ScanEvent::Warning(format!("w{i}")));
        }
        assert_eq!(view.log.len(), MAX_LOG_LINES);
        assert_eq!(
            view.log.last().unwrap(),
            &format!("{WARNING_PREFIX}w{}", MAX_LOG_LINES + 49)
        );
    }

    fn start_slow_scan(app: &mut App) {
        app.form.targets = "192.0.2.1".into();
        app.form.ports = "1-1000".into();
        app.form.discovery = false;
        press(app, KeyCode::Enter);
        press(app, KeyCode::Char('y'));
        assert!(matches!(app.screen, Screen::Results));
    }

    #[test]
    fn engine_vanishing_marks_the_scan_failed() {
        let (_rt, mut app) = app();
        start_slow_scan(&mut app);
        // Abort the engine behind the UI's back, as a panic would.
        app.scan.as_ref().unwrap().scan.stop();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !app.scan.as_ref().unwrap().failed {
            assert!(Instant::now() < deadline, "failure not detected");
            app.drain_events();
            std::thread::sleep(Duration::from_millis(10));
        }
        let view = app.scan.as_ref().unwrap();
        assert!(!view.is_running());
        assert!(view.log.iter().any(|l| l.contains("stopped unexpectedly")));
        assert!(render(&mut app, 100, 30).contains("failed"));
    }

    #[test]
    fn user_stop_is_not_a_failure() {
        let (_rt, mut app) = app();
        start_slow_scan(&mut app);
        press(&mut app, KeyCode::Char('s'));
        std::thread::sleep(Duration::from_millis(100));
        app.drain_events();
        let view = app.scan.as_ref().unwrap();
        assert!(view.stopped && !view.failed);
        assert!(render(&mut app, 100, 30).contains("stopped"));
    }

    #[test]
    fn leaving_a_running_scan_is_not_a_failure() {
        let (_rt, mut app) = app();
        start_slow_scan(&mut app);
        press(&mut app, KeyCode::Char('n'));
        assert!(matches!(app.screen, Screen::Setup));
        std::thread::sleep(Duration::from_millis(100));
        app.drain_events();
        let view = app.scan.as_ref().unwrap();
        assert!(view.stopped && !view.failed);
    }

    #[test]
    fn setup_screen_shows_log_status() {
        let (_rt, mut app) = app();
        // Logging isn't initialised in unit tests.
        assert!(render(&mut app, 90, 24).contains("logging off"));
    }
}
