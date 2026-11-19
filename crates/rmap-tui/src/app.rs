//! Application state and input handling.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use rmap_core::{
    HostName, HostState, MacAddr, PortList, PortResult, ScanEvent, ScanType, Timing, parse_targets,
};
use rmap_engine::{Scan, ScanConfig};
use rmap_report::{ReportBuilder, ScanStore, unix_millis_now};
use tokio::runtime::Handle;
use tokio::sync::mpsc::error::TryRecvError;

use crate::filter::SortOrder;
use crate::input::{TextInput, paste_as_list};
use crate::mouse::HitMap;
use crate::report::{Dialog, DiffView};

/// Most engine events handled per frame, so a burst can't stall input.
pub(crate) const EVENTS_PER_FRAME: usize = 5_000;
const MAX_LOG_LINES: usize = 200;
/// Marks engine warnings in the log panel, which draws them highlighted.
pub const WARNING_PREFIX: &str = "warning: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Targets,
    Exclude,
    Ports,
    ScanType,
    Timing,
    MaxRate,
    Discovery,
    Names,
    DnsServer,
    Services,
    Vulns,
}

impl Field {
    const ALL: [Field; 11] = [
        Field::Targets,
        Field::Exclude,
        Field::Ports,
        Field::ScanType,
        Field::Timing,
        Field::MaxRate,
        Field::Discovery,
        Field::Names,
        Field::DnsServer,
        Field::Services,
        Field::Vulns,
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
    pub targets: TextInput,
    /// Addresses never to probe, in target syntax.
    pub exclude: TextInput,
    pub ports: TextInput,
    /// Probes per second across the whole scan; empty means unlimited.
    pub max_rate: TextInput,
    pub scan_type: ScanType,
    pub timing: u8,
    pub discovery: bool,
    /// Look up host names (reverse DNS, NetBIOS, mDNS).
    pub resolve_names: bool,
    /// DNS server for reverse lookups; empty means the system's.
    pub dns_server: TextInput,
    pub service_detection: bool,
    /// Look up detected services' CPEs in the local CVE database (M4).
    /// Only takes effect with `service_detection` also on - there is
    /// nothing to look up otherwise.
    pub vuln_matching: bool,
    pub focus: Field,
    pub error: Option<String>,
}

impl Default for Form {
    fn default() -> Self {
        Form {
            targets: TextInput::default(),
            exclude: TextInput::default(),
            ports: "common".into(),
            max_rate: TextInput::default(),
            scan_type: ScanType::Connect,
            timing: 3,
            discovery: true,
            // Off in tests: their scans must not query the real DNS server.
            resolve_names: !cfg!(test),
            dns_server: TextInput::default(),
            service_detection: false,
            vuln_matching: false,
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
    /// Learned over ARP; only on the local subnet with raw sockets.
    pub mac: Option<MacAddr>,
    /// Names the host answered to, best first. The first also fills
    /// `hostname` when the user didn't type one.
    pub names: Vec<HostName>,
}

/// Which results pane the arrow keys move through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Hosts,
    Ports,
}

/// A yes/no question shown before a destructive key takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// Stop the running scan and go back to the setup form.
    StopAndLeave,
    /// Quit while a scan is still running.
    QuitRunning,
    /// Quit from the setup form.
    Quit,
    /// Delete the profile highlighted in the profile picker.
    DeleteProfile,
}

impl Confirm {
    pub fn question(self) -> &'static str {
        match self {
            Confirm::StopAndLeave => "Stop the running scan and start a new one?",
            Confirm::QuitRunning => "A scan is still running. Stop it and quit?",
            Confirm::Quit => "Quit rmap?",
            Confirm::DeleteProfile => "Delete the selected profile?",
        }
    }
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
    pub log: VecDeque<String>,
    /// The full-height log view (`L`): lines scrolled back from the newest,
    /// or `None` when closed. See `log_view.rs`.
    pub log_view: Option<usize>,
    /// Everything the engine reported, for export and saving.
    pub report: ReportBuilder,
    /// Where the scan was auto-saved, once it ended.
    pub saved: Option<PathBuf>,
    pub save_attempted: bool,
    pub focus: Pane,
    /// Selected open port (index into the selected host's `open`).
    pub port_selected: usize,
    /// First table row drawn in the port pane; kept by the renderer so the
    /// view only scrolls when the selection would leave it.
    pub port_offset: usize,
    /// Which results tab is shown, and the Services/Vulns tabs' selection.
    pub tabs: crate::tabs::Tabs,
    /// Host list filter text (`/`), and whether it has keyboard focus.
    pub filter: TextInput,
    pub filtering: bool,
    pub sort: SortOrder,
    /// Re-scan of one host (`r`), run after the main scan ends.
    pub rescan: Option<crate::rescan::Rescan>,
    /// Progress samples for the header's rate, ETA and sparkline.
    pub rate: crate::rate::RateMeter,
}

impl ScanView {
    pub fn is_running(&self) -> bool {
        self.finished.is_none() && !self.stopped && !self.failed
    }

    pub fn elapsed(&self) -> Duration {
        self.finished.unwrap_or_else(|| self.started.elapsed())
    }

    /// Hosts shown in the list, filtered and in the chosen sort order.
    pub fn visible(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = self
            .hosts
            .iter()
            .filter(|(_, h)| self.show_down || h.state != HostState::Down)
            .filter(|(ip, h)| crate::filter::matches(**ip, h, &self.filter))
            .map(|(ip, _)| *ip)
            .collect();
        crate::filter::sort(&mut ips, &self.hosts, self.sort);
        ips
    }

    /// After the filter or sort changes: keep the selected host if it is
    /// still listed, else select the first row (or nothing).
    pub(crate) fn keep_selection(&mut self) {
        let visible = self.visible();
        let keep = self
            .selected
            .filter(|s| visible.contains(s))
            .or(visible.first().copied());
        if keep != self.selected {
            self.selected = keep;
            self.port_selected = 0;
            self.port_offset = 0;
        }
    }

    pub fn count(&self, state: HostState) -> usize {
        self.hosts.values().filter(|h| h.state == state).count()
    }

    pub(crate) fn move_selection(&mut self, delta: isize) {
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
        if self.selected != Some(visible[next]) {
            self.port_selected = 0;
            self.port_offset = 0;
        }
        self.selected = Some(visible[next]);
    }

    /// Open ports on the selected host.
    pub fn selected_ports(&self) -> &[PortResult] {
        self.selected
            .and_then(|ip| self.hosts.get(&ip))
            .map_or(&[], |h| h.open.as_slice())
    }

    pub(crate) fn move_port_selection(&mut self, delta: isize) {
        let n = self.selected_ports().len();
        if n == 0 {
            return;
        }
        self.port_selected =
            (self.port_selected as isize + delta).clamp(0, n as isize - 1) as usize;
    }

    fn move_focused(&mut self, delta: isize) {
        match self.focus {
            Pane::Hosts => self.move_selection(delta),
            Pane::Ports => self.move_port_selection(delta),
        }
    }

    pub(crate) fn log(&mut self, line: String) {
        self.log.push_back(line);
        if self.log.len() > MAX_LOG_LINES {
            self.log.pop_front();
        }
    }

    pub(crate) fn apply(&mut self, event: ScanEvent) {
        self.report.apply(&event);
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
                        mac: None,
                        names: Vec::new(),
                    },
                );
                // With a filter on, drain_events picks the first match instead.
                if self.selected.is_none() && state != HostState::Down && self.filter.is_empty() {
                    self.selected = Some(ip);
                }
            }
            ScanEvent::Mac { ip, mac } => match self.hosts.get_mut(&ip) {
                Some(host) => host.mac = Some(mac),
                None => rmap_log::warn!("MAC for {ip} arrived before its host"),
            },
            ScanEvent::Hostnames { ip, names } => match self.hosts.get_mut(&ip) {
                Some(host) => {
                    if host.hostname.is_none() {
                        host.hostname = names.first().map(|n| n.name.clone());
                    }
                    host.names = names;
                }
                None => rmap_log::warn!("names for {ip} arrived before its host"),
            },
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
            ScanEvent::Vulnerabilities {
                ip,
                protocol,
                port,
                findings,
            } => {
                let found = self.hosts.get_mut(&ip).and_then(|h| {
                    h.open
                        .iter_mut()
                        .find(|p| p.port == port && p.protocol == protocol)
                });
                match found {
                    Some(p) => p.vulnerabilities = findings,
                    None => rmap_log::warn!(
                        "vulnerabilities for {ip} {port}/{} arrived before its port",
                        protocol.as_str()
                    ),
                }
            }
            ScanEvent::VulnCheck {
                ip,
                protocol,
                port,
                status,
            } => {
                let found = self.hosts.get_mut(&ip).and_then(|h| {
                    h.open
                        .iter_mut()
                        .find(|p| p.port == port && p.protocol == protocol)
                });
                match found {
                    Some(p) => p.vuln_check = Some(status),
                    None => rmap_log::warn!(
                        "CVE check status for {ip} {port}/{} arrived before its port",
                        protocol.as_str()
                    ),
                }
            }
            // The report builder keeps it; the header reads it from there.
            ScanEvent::VulnData(_) => {}
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
    /// Comparing the current scan with a saved one.
    Diff,
}

pub struct App {
    pub(crate) rt: Handle,
    pub screen: Screen,
    pub form: Form,
    pub scan: Option<ScanView>,
    /// A scan waiting on the user to confirm it may touch public addresses.
    pub pending: Option<(ScanConfig, Vec<String>)>,
    /// Saved scans and exports; `None` turns saving off (unit tests).
    pub store: Option<ScanStore>,
    /// Export dialog or saved-scan picker over the results screen.
    pub dialog: Option<Dialog>,
    pub diff: Option<DiffView>,
    /// A destructive key waiting on y/n.
    pub confirm: Option<Confirm>,
    /// Vulns was ticked with no usable CVE data: the pop-up pointing to
    /// Settings. `Some(true)` when the tick also turned Services on.
    pub vuln_popup: Option<bool>,
    /// The key help overlay on the results screen.
    pub help: bool,
    /// Scan profiles, recent targets, and their pickers on the setup form.
    pub profiles: crate::profiles::Profiles,
    /// Text for the event loop to send to the clipboard (OSC 52).
    pub clipboard: Option<String>,
    /// Whether the terminal should report mouse events; `m` toggles it.
    pub mouse_capture: bool,
    /// Clickable areas of the last frame, written by the renderer.
    pub hits: HitMap,
    /// Settings, the CVE data status and the Settings screen (`settings_ui.rs`).
    pub settings: crate::settings_ui::SettingsState,
    quit: bool,
}

impl App {
    pub fn new(rt: Handle) -> Self {
        let store = crate::report::default_store();
        let profiles = crate::profiles::Profiles::load(store.as_ref().map(ScanStore::dir));
        App {
            rt,
            screen: Screen::Setup,
            form: Form::default(),
            scan: None,
            pending: None,
            store,
            dialog: None,
            diff: None,
            confirm: None,
            vuln_popup: None,
            help: false,
            profiles,
            clipboard: None,
            mouse_capture: true,
            hits: HitMap::default(),
            settings: crate::settings_ui::SettingsState::from_env(),
            quit: false,
        }
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub(crate) fn request_quit(&mut self) {
        self.quit = true;
    }

    /// Pull whatever the engine has produced since the last frame.
    pub fn drain_events(&mut self) {
        self.poll_settings();
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
        if view.selected.is_none() {
            view.keep_selection();
        }
        view.drain_rescan();
        if view.is_running() {
            let done = view
                .scan
                .progress
                .completed
                .load(std::sync::atomic::Ordering::Relaxed);
            view.rate.sample(view.started.elapsed(), done);
        }
        self.autosave_if_done();
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        rmap_log::trace!("key {:?} {:?}", key.code, key.modifiers);
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            rmap_log::info!("quit via ctrl-c");
            self.quit = true;
            return;
        }
        if let Some(confirm) = self.confirm {
            self.on_yes_no_key(confirm, key);
            return;
        }
        if self.pending.is_some() {
            self.on_confirm_key(key);
            return;
        }
        if self.vuln_popup.is_some() {
            match key.code {
                KeyCode::Enter | KeyCode::F(2) => {
                    self.vuln_popup = None;
                    self.open_settings();
                }
                KeyCode::Esc => self.vuln_popup = None,
                _ => {}
            }
            return;
        }
        if self.settings.is_open() {
            self.on_settings_key(key);
            return;
        }
        if self.help {
            // Any key closes the overlay; it doesn't fall through.
            self.help = false;
            return;
        }
        if self.profiles.picker.is_some() {
            self.on_picker_key(key);
            return;
        }
        if self.dialog.is_some() {
            self.on_dialog_key(key);
            return;
        }
        match self.screen {
            Screen::Setup => self.on_setup_key(key),
            Screen::Results => self.on_results_key(key),
            Screen::Diff => self.on_diff_key(key),
        }
    }

    /// Bracketed paste. Multi-line text arrives here in one piece instead
    /// of as keypresses, so a newline in it can't submit the form.
    pub fn on_paste(&mut self, pasted: &str) {
        rmap_log::debug!("paste of {} bytes", pasted.len());
        if self.confirm.is_some()
            || self.pending.is_some()
            || self.vuln_popup.is_some()
            || self.help
        {
            return;
        }
        if self.settings.is_open() {
            self.on_settings_paste(pasted);
            return;
        }
        if self.profiles.picker.is_some() {
            self.profiles.paste(pasted);
            return;
        }
        if let Some(Dialog::Export(d)) = self.dialog.as_mut() {
            d.path
                .insert_str(pasted.lines().next().unwrap_or("").trim());
            d.status = None;
            return;
        }
        if let Some(view) = self.scan.as_mut()
            && view.filtering
            && matches!(self.screen, Screen::Results)
        {
            view.filter
                .insert_str(pasted.lines().next().unwrap_or("").trim());
            view.keep_selection();
            return;
        }
        if !matches!(self.screen, Screen::Setup) || self.dialog.is_some() {
            return;
        }
        let form = &mut self.form;
        match form.focus {
            Field::Targets => form.targets.insert_str(&paste_as_list(pasted)),
            Field::Exclude => form.exclude.insert_str(&paste_as_list(pasted)),
            Field::Ports => form.ports.insert_str(&paste_as_list(pasted)),
            Field::MaxRate => form
                .max_rate
                .insert_str(pasted.lines().next().unwrap_or("").trim()),
            Field::DnsServer => form
                .dns_server
                .insert_str(pasted.lines().next().unwrap_or("").trim()),
            _ => {}
        }
    }

    fn on_yes_no_key(&mut self, confirm: Confirm, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.confirm = None;
                rmap_log::info!("user confirmed: {confirm:?}");
                match confirm {
                    Confirm::Quit | Confirm::QuitRunning => self.quit = true,
                    Confirm::DeleteProfile => self.delete_selected_profile(),
                    Confirm::StopAndLeave => {
                        if let Some(view) = self.scan.as_mut()
                            && view.is_running()
                        {
                            view.scan.stop();
                            view.stopped = true;
                        }
                        self.screen = Screen::Setup;
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.confirm = None,
            _ => {}
        }
    }

    fn on_confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some((config, _)) = self.pending.take() {
                    rmap_log::info!("user confirmed scanning public addresses");
                    // Only a rescan asks from the results screen.
                    if matches!(self.screen, Screen::Results) {
                        self.start_rescan(config);
                    } else {
                        self.launch(config);
                    }
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
        if self.on_profiles_shortcut(&key) {
            return;
        }
        let form = &mut self.form;
        match key.code {
            KeyCode::F(2) => self.open_settings(),
            KeyCode::Esc => self.confirm = Some(Confirm::Quit),
            KeyCode::Enter => self.submit(),
            KeyCode::Tab | KeyCode::Down => form.focus = form.focus.step(true),
            KeyCode::BackTab | KeyCode::Up => form.focus = form.focus.step(false),
            code => match form.focus {
                Field::Targets => {
                    form.targets.handle_key(&key);
                }
                Field::Ports => {
                    form.ports.handle_key(&key);
                }
                Field::Exclude => {
                    form.exclude.handle_key(&key);
                }
                Field::MaxRate => {
                    form.max_rate.handle_key(&key);
                }
                Field::DnsServer => {
                    form.dns_server.handle_key(&key);
                }
                Field::Names => {
                    if matches!(code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) {
                        form.resolve_names = !form.resolve_names;
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
                        if !form.service_detection {
                            form.vuln_matching = false;
                        }
                    }
                }
                Field::Vulns => {
                    if matches!(code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) {
                        form.vuln_matching = !form.vuln_matching;
                        // CVE matching needs detected versions; turn
                        // Services on rather than accept a no-op setting.
                        if form.vuln_matching {
                            let services_was_on = form.service_detection;
                            form.service_detection = true;
                            self.vulns_ticked(services_was_on);
                        }
                    }
                }
            },
        }
    }

    /// Vulns was just turned on: re-read the CVE data (here, not per frame)
    /// and point to Settings when there's none to match against.
    pub(crate) fn vulns_ticked(&mut self, services_was_on: bool) {
        let s = &mut self.settings;
        s.db = crate::settings_ui::DbStatus::read(s.db_path.as_deref());
        if s.db.needs_download() {
            rmap_log::info!("Vulns ticked without usable CVE data: {:?}", s.db);
            self.vuln_popup = Some(!services_was_on);
        }
    }

    fn on_results_key(&mut self, key: KeyEvent) {
        let Some(view) = self.scan.as_mut() else {
            self.screen = Screen::Setup;
            return;
        };
        if view.filtering {
            match key.code {
                KeyCode::Enter => view.filtering = false,
                KeyCode::Esc => {
                    view.filter.clear();
                    view.filtering = false;
                }
                _ => {
                    view.filter.handle_key(&key);
                }
            }
            view.keep_selection();
            return;
        }
        if crate::log_view::on_key(view, &key) || crate::tabs::on_key(view, key.code) {
            return;
        }
        match key.code {
            KeyCode::Char('/') => {
                view.filtering = true;
                view.focus = Pane::Hosts;
            }
            KeyCode::Char('o') => {
                view.sort = view.sort.next();
                view.keep_selection();
            }
            // Esc clears an active filter before it means "new scan".
            KeyCode::Esc if !view.filter.is_empty() => {
                view.filter.clear();
                view.keep_selection();
            }
            KeyCode::Char('q') => {
                if view.is_running() {
                    self.confirm = Some(Confirm::QuitRunning);
                } else {
                    rmap_log::info!("quit from results screen");
                    self.quit = true;
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                if view.is_running() {
                    self.confirm = Some(Confirm::StopAndLeave);
                } else {
                    rmap_log::debug!("back to setup screen");
                    self.screen = Screen::Setup;
                }
            }
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('S') | KeyCode::F(2) => self.open_settings(),
            KeyCode::Tab | KeyCode::BackTab => {
                view.focus = match view.focus {
                    Pane::Hosts => Pane::Ports,
                    Pane::Ports => Pane::Hosts,
                }
            }
            KeyCode::Right | KeyCode::Char('l') => view.focus = Pane::Ports,
            KeyCode::Char('L') => view.log_view = Some(0),
            KeyCode::Left | KeyCode::Char('h') => view.focus = Pane::Hosts,
            KeyCode::Char('s') if view.is_running() => {
                view.scan.stop();
                view.stopped = true;
                view.log("scan stopped".into());
            }
            KeyCode::Char('d') => {
                view.show_down = !view.show_down;
                view.keep_selection();
            }
            KeyCode::Char('s') if view.rescan.is_some() => view.stop_rescan(),
            KeyCode::Char('r') => self.request_rescan(),
            KeyCode::Char('e') => self.open_export(),
            KeyCode::Char('c') => self.open_compare(),
            KeyCode::Char('y') => self.clipboard = crate::clipboard::copy_selection(view, false),
            KeyCode::Char('Y') => self.clipboard = crate::clipboard::copy_selection(view, true),
            KeyCode::Char('m') => self.toggle_mouse_capture(),
            KeyCode::Down | KeyCode::Char('j') => view.move_focused(1),
            KeyCode::Up | KeyCode::Char('k') => view.move_focused(-1),
            KeyCode::PageDown => view.move_focused(10),
            KeyCode::PageUp => view.move_focused(-10),
            KeyCode::Home | KeyCode::Char('g') => view.move_focused(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => view.move_focused(isize::MAX / 2),
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
        let exclude = match crate::limits::parse_exclude(&form.exclude) {
            Ok(e) => e,
            Err(e) => {
                rmap_log::info!("rejected exclude {:?}: {e}", form.exclude);
                form.error = Some(format!("Exclude: {e}"));
                form.focus = Field::Exclude;
                return;
            }
        };
        if !exclude.is_empty() && rmap_engine::exclude::count_hosts(&targets, &exclude) == 0 {
            rmap_log::info!("rejected scan: every target is excluded");
            form.error = Some("Exclude: every target address is excluded; nothing to scan".into());
            form.focus = Field::Exclude;
            return;
        }
        let max_rate = match crate::limits::parse_max_rate(&form.max_rate) {
            Ok(r) => r,
            Err(e) => {
                rmap_log::info!("rejected max rate {:?}: {e}", form.max_rate);
                form.error = Some(format!("Max rate: {e}"));
                form.focus = Field::MaxRate;
                return;
            }
        };
        let dns_server = match crate::limits::parse_dns_server(&form.dns_server) {
            Ok(s) => s,
            Err(e) => {
                rmap_log::info!("rejected DNS server {:?}: {e}", form.dns_server);
                form.error = Some(format!("DNS server: {e}"));
                form.focus = Field::DnsServer;
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
            vuln_matching: form.vuln_matching,
            exclude,
            max_rate,
            resolve_names: form.resolve_names,
            dns_server,
            vuln_db: None,
        };
        if public.is_empty() {
            self.launch(config);
        } else {
            rmap_log::info!("asking to confirm public targets: {public:?}");
            self.pending = Some((config, public));
        }
    }

    fn launch(&mut self, config: ScanConfig) {
        // Save the previous scan before it's replaced.
        self.autosave_if_done();
        self.profiles.remember_targets(&self.form.targets);
        let report = ReportBuilder::new(
            crate::report::config_summary(&self.form.targets, &self.form.exclude, &config),
            unix_millis_now(),
        );
        let mut summary = format!(
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
        // Rate first: the exclude list can be long and the title truncates.
        if let Some(rate) = config.max_rate {
            summary += &format!(" · max {rate}/s");
        }
        if !config.exclude.is_empty() {
            summary += &format!(" · excluding {}", self.form.exclude.trim());
        }
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
            log: VecDeque::new(),
            log_view: None,
            report,
            saved: None,
            save_attempted: false,
            focus: Pane::Hosts,
            port_selected: 0,
            port_offset: 0,
            tabs: Default::default(),
            filter: TextInput::default(),
            filtering: false,
            sort: SortOrder::default(),
            rescan: None,
            rate: Default::default(),
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
        app.form.ports = port.to_string().into();
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
            Field::Exclude,
            Field::Ports,
            Field::ScanType,
            Field::Timing,
            Field::MaxRate,
            Field::Discovery,
            Field::Names,
            Field::DnsServer,
            Field::Services,
            Field::Vulns,
            Field::Targets,
        ] {
            press(&mut app, KeyCode::Tab);
            assert_eq!(app.form.focus, expected);
        }
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.form.focus, Field::Vulns);
    }

    #[test]
    fn editing_text_fields() {
        let (_rt, mut app) = app();
        type_text(&mut app, "10.0.0.1x");
        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.form.targets, "10.0.0.1");
        app.form.focus = Field::Ports;
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
        assert_eq!(app.confirm, Some(Confirm::Quit), "asks first");
        assert!(render(&mut app, 80, 24).contains("Quit rmap?"));
        press(&mut app, KeyCode::Char('n'));
        assert!(!app.should_quit() && app.confirm.is_none());
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Char('y'));
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

    /// Open `ports` on `ip` and attach `service(port)` to each.
    fn open_with(
        app: &mut App,
        ip: IpAddr,
        ports: &[u16],
        service: impl Fn(u16) -> rmap_core::Service,
    ) {
        let view = app.scan.as_mut().unwrap();
        for &port in ports {
            let open = rmap_core::PortState::Open;
            view.apply(ScanEvent::Port {
                ip,
                result: PortResult::new(port, Protocol::Tcp, open, None),
            });
            view.apply(ScanEvent::Service {
                ip,
                protocol: Protocol::Tcp,
                port,
                service: service(port),
            });
        }
        view.selected = Some(ip);
    }

    #[test]
    fn port_table_guesses_render_with_a_question_mark() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        open_with(&mut app, ip, &[22, 7001], |port| rmap_core::Service {
            name: if port == 22 { "ssh" } else { "weblogic" }.into(),
            method: if port == 22 {
                rmap_core::DetectMethod::Probe
            } else {
                rmap_core::DetectMethod::PortTable
            },
            ..Default::default()
        });
        let screen = render(&mut app, 110, 30);
        assert!(screen.contains("weblogic?"), "{screen}");
        assert!(
            screen.contains("ssh ") && !screen.contains("ssh?"),
            "{screen}"
        );
        assert!(!screen.contains("silent"), "{screen}");
    }

    #[test]
    fn all_silent_ports_get_a_host_hint() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        open_with(&mut app, ip, &[21, 22, 25, 80, 445], |port| {
            rmap_core::Service {
                name: rmap_core::service_name(port).unwrap().into(),
                info: Some(rmap_core::SILENT_INFO.into()),
                confidence: 1,
                ..Default::default()
            }
        });
        let screen = render(&mut app, 120, 30);
        assert!(screen.contains("likely a firewall or IPS"), "{screen}");
        assert!(screen.contains("smb?"), "{screen}");
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
            info: Some("protocol 2.0".into()),
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
        // Regression: the detail row's leading placeholder cells must be
        // real empty cells (Cell::from("")), not Cell::default() (column
        // span 0), or this line collapses into column 0 and gets cut to
        // ~10 characters.
        assert!(screen.contains("protocol 2.0"), "{screen}");
    }

    #[test]
    fn vulnerability_events_attach_to_their_port() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let view = app.scan.as_mut().unwrap();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        view.apply(ScanEvent::Port {
            ip,
            result: PortResult::new(22, Protocol::Tcp, rmap_core::PortState::Open, None),
        });
        view.apply(ScanEvent::Vulnerabilities {
            ip,
            protocol: Protocol::Tcp,
            port: 22,
            findings: vec![rmap_core::Vulnerability {
                id: "CVE-2024-6387".into(),
                summary: "regreSSHion".into(),
                severity: rmap_core::VulnSeverity::High,
                score: Some(8.1),
                published: None,
                kev_added: None,
            }],
        });
        let host = &view.hosts[&ip];
        assert_eq!(host.open[0].vulnerabilities.len(), 1);
        app.scan.as_mut().unwrap().selected = Some(ip);
        let screen = render(&mut app, 160, 30);
        assert!(
            screen.contains("CVE-2024-6387") && screen.contains("regreSSHion"),
            "{screen}"
        );
    }

    #[test]
    fn vulnerabilities_for_an_unknown_port_are_logged_not_lost() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        let view = app.scan.as_mut().unwrap();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        // No matching Port event first - this should warn, not panic.
        view.apply(ScanEvent::Vulnerabilities {
            ip,
            protocol: Protocol::Tcp,
            port: 9999,
            findings: vec![rmap_core::Vulnerability {
                id: "CVE-0000-0000".into(),
                summary: "test".into(),
                severity: rmap_core::VulnSeverity::Low,
                score: None,
                published: None,
                kev_added: None,
            }],
        });
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
        app.form.focus = Field::Vulns;
        press(&mut app, KeyCode::Char(' '));
        assert!(app.form.vuln_matching);
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
            view.log.back().unwrap(),
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
        assert_eq!(app.confirm, Some(Confirm::StopAndLeave));
        assert!(app.scan.as_ref().unwrap().is_running(), "nothing stops yet");
        press(&mut app, KeyCode::Char('y'));
        assert!(matches!(app.screen, Screen::Setup));
        std::thread::sleep(Duration::from_millis(100));
        app.drain_events();
        let view = app.scan.as_ref().unwrap();
        assert!(view.stopped && !view.failed);
    }

    /// The review's sample: a NAS with five open ports, OpenSSH with two
    /// CVEs, nginx with TLS, and an open|filtered port at the bottom.
    fn nas_host(app: &mut App) -> IpAddr {
        fake_results(app);
        let view = app.scan.as_mut().unwrap();
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        view.apply(ScanEvent::Host {
            ip,
            hostname: Some("nas01.springer.local".into()),
            state: HostState::Up,
            rtt: Some(Duration::from_micros(1100)),
        });
        let open = rmap_core::PortState::Open;
        for (port, state) in [
            (22, open),
            (80, open),
            (443, open),
            (445, open),
            (5000, rmap_core::PortState::OpenFiltered),
        ] {
            view.apply(ScanEvent::Port {
                ip,
                result: PortResult::new(port, Protocol::Tcp, state, None),
            });
        }
        view.apply(ScanEvent::Service {
            ip,
            protocol: Protocol::Tcp,
            port: 22,
            service: rmap_core::Service {
                name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: Some("8.9p1".into()),
                info: Some("protocol 2.0".into()),
                os_hint: Some("Ubuntu Linux".into()),
                cpes: vec!["cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*".into()],
                ..Default::default()
            },
        });
        let cve = |id: &str, summary: &str, severity, score| rmap_core::Vulnerability {
            id: id.into(),
            summary: summary.into(),
            severity,
            score: Some(score),
            published: None,
            kev_added: None,
        };
        view.apply(ScanEvent::Vulnerabilities {
            ip,
            protocol: Protocol::Tcp,
            port: 22,
            findings: vec![
                cve(
                    "CVE-2024-6387",
                    "regreSSHion: unauthenticated remote code execution in sshd on glibc-based Linux systems",
                    rmap_core::VulnSeverity::High,
                    8.1,
                ),
                cve(
                    "CVE-2023-48795",
                    "Terrapin: prefix truncation weakens SSH channel integrity",
                    rmap_core::VulnSeverity::Medium,
                    5.9,
                ),
            ],
        });
        view.apply(ScanEvent::Service {
            ip,
            protocol: Protocol::Tcp,
            port: 443,
            service: rmap_core::Service {
                name: "https".into(),
                product: Some("nginx".into()),
                version: Some("1.24.0".into()),
                info: Some("TLS cert CN=nas01.springer.local".into()),
                ..Default::default()
            },
        });
        view.selected = Some(ip);
        ip
    }

    #[test]
    fn cve_lines_are_whole_at_80_and_120_columns() {
        let (_rt, mut app) = app();
        nas_host(&mut app);
        for (w, h) in [(120, 32), (80, 24)] {
            let screen = render(&mut app, w, h);
            for needle in [
                "CVE-2024-6387",
                "regreSSHion",
                "glibc-based", // the end of the summary, wrapped
                "HIGH",
                "OpenSSH 8.9p1",
                "protocol 2.0",
                "nas01.springer.local",
            ] {
                assert!(screen.contains(needle), "{needle} at {w}x{h}:\n{screen}");
            }
            assert!(
                !screen
                    .lines()
                    .any(|l| l.contains("/tcp") && l.contains("open|filtered")),
                "short label in table:\n{screen}"
            );
            if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
                println!("{screen}");
            }
        }
    }

    #[test]
    fn header_shows_rate_eta_and_sparkline() {
        use std::sync::atomic::Ordering::Relaxed;
        let (_rt, mut app) = app();
        nas_host(&mut app);
        let view = app.scan.as_mut().unwrap();
        // Pretend it's still running: 380 probes/s for six seconds.
        view.stopped = false;
        for s in 0..=6 {
            view.rate
                .sample(Duration::from_secs(s), 15_840 - (6 - s) * 380);
        }
        view.scan.progress.total.store(25_400, Relaxed);
        view.scan.progress.completed.store(15_840, Relaxed);
        for (w, h) in [(120, 32), (80, 24)] {
            let screen = render(&mut app, w, h);
            let header: String = screen.lines().take(4).collect::<Vec<_>>().join("\n");
            for needle in ["ETA 0:25", "15,840 / 25,400 probes · 380/s ██████"] {
                assert!(header.contains(needle), "{needle} at {w}x{h}:\n{header}");
            }
            if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
                println!("{screen}");
            }
        }
        // Narrow: the sparkline goes, then the rate; nothing panics.
        let header = render(&mut app, 59, 24);
        assert!(
            header.contains("380/s") && !header.contains("380/s █"),
            "{header}"
        );
        let header = render(&mut app, 52, 24);
        assert!(header.contains("25,400 probes") && !header.contains("380/s"));
        assert!(!render(&mut app, 44, 24).contains("probes"));
        for (w, h) in [(20, 6), (1, 1)] {
            render(&mut app, w, h);
        }
        // Stopped: no ETA and no rate.
        app.scan.as_mut().unwrap().stopped = true;
        let screen = render(&mut app, 120, 32);
        assert!(!screen.contains("ETA"), "{screen}");
        assert!(screen.contains("25,400 probes│"), "{screen}");
        // Finished: the whole-scan average and the final duration.
        let view = app.scan.as_mut().unwrap();
        view.stopped = false;
        view.finished = Some(Duration::from_secs(40));
        let screen = render(&mut app, 120, 32);
        assert!(!screen.contains("ETA"), "{screen}");
        assert!(
            screen.contains("· 396/s") && screen.contains("· 40.0s"),
            "{screen}"
        );
    }

    #[test]
    fn port_pane_scrolls_to_the_last_port() {
        let (_rt, mut app) = app();
        nas_host(&mut app);
        let screen = render(&mut app, 80, 24);
        assert!(
            !screen.contains("5000/tcp"),
            "off screen at first:\n{screen}"
        );
        assert!(screen.contains("↓ more"), "{screen}");
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::End);
        let view = app.scan.as_ref().unwrap();
        assert_eq!((view.focus, view.port_selected), (Pane::Ports, 4));
        let screen = render(&mut app, 80, 24);
        assert!(screen.contains("5000/tcp"), "{screen}");
        assert!(screen.contains("open?"), "{screen}");
        // Moving hosts resets the port selection.
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.scan.as_ref().unwrap().port_selected, 0);
    }

    #[test]
    fn narrow_terminals_keep_names_and_footer() {
        let (_rt, mut app) = app();
        nas_host(&mut app);
        let screen = render(&mut app, 80, 24);
        let footer = screen.lines().last().unwrap();
        assert!(
            footer.contains("help") && footer.contains("quit"),
            "{footer}"
        );
        // Stacked layout: the host table has the full width for names.
        let host_row = screen
            .lines()
            .find(|l| l.contains("192.168.1.20 "))
            .unwrap();
        assert!(host_row.contains("nas01.springer.local"), "{host_row}");
        assert!(
            host_row.contains("OPEN") || host_row.contains('!'),
            "{host_row}"
        );
        // Nothing panics down to tiny sizes.
        for (w, h) in [(40, 12), (20, 6), (1, 1)] {
            render(&mut app, w, h);
        }
    }

    #[test]
    fn help_overlay_opens_and_closes() {
        let (_rt, mut app) = app();
        fake_results(&mut app);
        press(&mut app, KeyCode::Char('?'));
        assert!(render(&mut app, 80, 24).contains("switch between hosts and ports"));
        press(&mut app, KeyCode::Char('d'));
        assert!(!app.help);
        assert!(
            !app.scan.as_ref().unwrap().show_down,
            "the key only closed help"
        );
    }

    #[test]
    fn y_copies_the_selection() {
        let (_rt, mut app) = app();
        let ip = nas_host(&mut app);
        let last_log = |app: &App| app.scan.as_ref().unwrap().log.back().cloned().unwrap();
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(app.clipboard.take().as_deref(), Some("192.168.1.20"));
        assert_eq!(last_log(&app), "copied 192.168.1.20");
        // Host pane: every CVE on the host, deduplicated.
        let view = app.scan.as_mut().unwrap();
        let dup = view.hosts[&ip].open[0].vulnerabilities[0].clone();
        view.hosts.get_mut(&ip).unwrap().open[2]
            .vulnerabilities
            .push(dup);
        press(&mut app, KeyCode::Char('Y'));
        assert_eq!(
            app.clipboard.take().as_deref(),
            Some("CVE-2024-6387,CVE-2023-48795")
        );
        assert_eq!(last_log(&app), "copied 2 CVE IDs from 192.168.1.20");

        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(app.clipboard.take().as_deref(), Some("192.168.1.20:22"));
        assert_eq!(last_log(&app), "copied 192.168.1.20:22");
        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Char('Y'));
        assert_eq!(app.clipboard.take(), None);
        assert_eq!(last_log(&app), "nothing to copy: no CVEs on this port");
        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Char('Y'));
        assert_eq!(app.clipboard.take().as_deref(), Some("CVE-2024-6387"));
        for (w, h) in [(80, 24), (120, 32)] {
            assert!(render(&mut app, w, h).contains("copied 1 CVE ID from"));
        }
        press(&mut app, KeyCode::Char('?'));
        assert!(render(&mut app, 80, 24).contains("ip:port / CVE IDs"));
        press(&mut app, KeyCode::Esc);

        // IPv6 gets brackets; a host with no open ports has nothing to copy.
        let view = app.scan.as_mut().unwrap();
        let v6: IpAddr = "fe80::1".parse().unwrap();
        view.apply(ScanEvent::Host {
            ip: v6,
            hostname: None,
            state: HostState::Up,
            rtt: None,
        });
        view.selected = Some(v6);
        view.port_selected = 0;
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(app.clipboard.take(), None);
        assert_eq!(last_log(&app), "nothing to copy: no open port selected");
        app.scan.as_mut().unwrap().apply(ScanEvent::Port {
            ip: v6,
            result: PortResult::new(22, Protocol::Tcp, rmap_core::PortState::Open, None),
        });
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(app.clipboard.take().as_deref(), Some("[fe80::1]:22"));
    }

    #[test]
    fn oversized_copies_are_refused() {
        let (_rt, mut app) = app();
        let ip = nas_host(&mut app);
        let view = app.scan.as_mut().unwrap();
        let mut cve = view.hosts[&ip].open[0].vulnerabilities[0].clone();
        let ports = &mut view.hosts.get_mut(&ip).unwrap().open;
        for i in 0..1000 {
            cve.id = format!("CVE-2099-{i:05}");
            ports[1].vulnerabilities.push(cve.clone());
        }
        press(&mut app, KeyCode::Char('Y'));
        assert_eq!(app.clipboard, None);
        let log = app.scan.as_ref().unwrap().log.back().unwrap();
        assert!(
            log.starts_with("nothing copied:") && log.contains("limit"),
            "{log}"
        );
    }

    #[test]
    fn multi_line_paste_does_not_submit() {
        let (_rt, mut app) = app();
        app.on_paste("10.0.0.1\r\n10.0.0.2\n\n10.0.0.3\n");
        assert!(matches!(app.screen, Screen::Setup));
        assert_eq!(app.form.targets, "10.0.0.1,10.0.0.2,10.0.0.3");
        // Paste inserts at the cursor, and the cursor keys edit mid-text.
        press(&mut app, KeyCode::Home);
        app.on_paste("10.0.0.9,");
        assert_eq!(app.form.targets, "10.0.0.9,10.0.0.1,10.0.0.2,10.0.0.3");
        app.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(app.form.targets, "");
        // Pastes into a toggle field are ignored.
        app.form.focus = Field::Timing;
        app.on_paste("5");
        assert_eq!(app.form.timing, 3);
    }

    #[test]
    fn quitting_a_running_scan_asks_first() {
        let (_rt, mut app) = app();
        start_slow_scan(&mut app);
        press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.confirm, Some(Confirm::QuitRunning));
        assert!(render(&mut app, 80, 24).contains("Stop it and quit?"));
        press(&mut app, KeyCode::Esc);
        assert!(!app.should_quit() && app.scan.as_ref().unwrap().is_running());
        press(&mut app, KeyCode::Char('q'));
        press(&mut app, KeyCode::Char('y'));
        assert!(app.should_quit());
    }

    #[test]
    fn vulns_needs_services() {
        let (_rt, mut app) = app();
        app.form.focus = Field::Vulns;
        assert!(render(&mut app, 90, 24).contains("needs Services"));
        press(&mut app, KeyCode::Char(' '));
        assert!(app.form.vuln_matching && app.form.service_detection);
        app.form.focus = Field::Services;
        press(&mut app, KeyCode::Char(' '));
        assert!(!app.form.vuln_matching && !app.form.service_detection);
    }

    #[test]
    fn filter_narrows_hosts_and_keeps_selection_valid() {
        let (_rt, mut app) = app();
        let nas = nas_host(&mut app);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        press(&mut app, KeyCode::Tab); // focus ports, select the last one
        press(&mut app, KeyCode::End);
        press(&mut app, KeyCode::Char('/'));
        type_text(&mut app, "SMB");
        let view = app.scan.as_ref().unwrap();
        assert_eq!(view.visible(), [nas], "only the host with 445 open");
        assert_eq!((view.focus, view.selected), (Pane::Hosts, Some(nas)));
        assert_eq!(view.port_selected, 4, "same host, port selection kept");
        for (w, h) in [(80, 24), (120, 32)] {
            let screen = render(&mut app, w, h);
            assert!(screen.contains("filter: /SMB"), "{w}x{h}:\n{screen}");
            assert!(screen.contains("1 of 3"), "{w}x{h}:\n{screen}");
            if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
                println!("{screen}");
            }
        }
        // Keys type into the filter while it has focus, even q and n.
        type_text(&mut app, "qn");
        assert!(!app.should_quit() && matches!(app.screen, Screen::Results));
        let view = app.scan.as_ref().unwrap();
        assert!(view.visible().is_empty());
        assert_eq!(view.selected, None, "nothing listed, nothing selected");
        assert!(render(&mut app, 80, 24).contains("no hosts match"));
        app.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        app.on_paste("10.0.0.3\nignored");
        press(&mut app, KeyCode::Enter);
        let view = app.scan.as_ref().unwrap();
        assert!(!view.filtering && view.filter == "10.0.0.3");
        assert_eq!(view.visible(), [ip("10.0.0.3")]);
        assert_eq!(
            (view.selected, view.port_selected),
            (Some(ip("10.0.0.3")), 0)
        );
        // Esc on the list clears the filter instead of leaving the results.
        press(&mut app, KeyCode::Esc);
        let view = app.scan.as_ref().unwrap();
        assert!(view.filter.is_empty() && matches!(app.screen, Screen::Results));
        assert_eq!(view.visible().len(), 3);
        assert_eq!(
            view.selected,
            Some(ip("10.0.0.3")),
            "kept when still listed"
        );
        // Esc while typing clears too.
        press(&mut app, KeyCode::Char('/'));
        type_text(&mut app, "nas");
        press(&mut app, KeyCode::Esc);
        let view = app.scan.as_ref().unwrap();
        assert!(!view.filtering && view.filter.is_empty());
        for (w, h) in [(20, 6), (1, 1)] {
            render(&mut app, w, h);
        }
    }

    #[test]
    fn o_cycles_sort_and_shows_it() {
        let (_rt, mut app) = app();
        let nas = nas_host(&mut app);
        assert!(render(&mut app, 80, 24).contains("by ip"));
        press(&mut app, KeyCode::Char('o'));
        let view = app.scan.as_ref().unwrap();
        assert_eq!(view.visible()[0], nas, "most open ports first");
        assert_eq!(view.selected, Some(nas));
        assert!(render(&mut app, 120, 32).contains("by ports"));
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(
            app.scan.as_ref().unwrap().visible()[0],
            nas,
            "worst CVE first"
        );
        assert!(render(&mut app, 80, 24).contains("by cves"));
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.scan.as_ref().unwrap().sort, SortOrder::Ip);
    }

    #[test]
    fn setup_screen_shows_log_status() {
        let (_rt, mut app) = app();
        // Logging isn't initialised in unit tests.
        assert!(render(&mut app, 90, 24).contains("logging off"));
    }

    /// Points the app at `vulns.db` in a fresh directory, written as a real
    /// (empty) database when `with_data`, so tests don't see this machine's.
    fn cve_data(app: &mut App, with_data: bool) -> crate::settings::TempDir {
        let dir = crate::settings::TempDir::new("vuln-popup");
        let path = dir.0.join("vulns.db");
        if with_data {
            let mut w = rmap_vuln::Writer::create(&path).unwrap();
            w.set_meta("built_at", "2026-11-01").unwrap();
            w.set_meta("source", "test").unwrap();
            w.finish().unwrap();
        }
        app.settings.db_path = Some(path);
        app.settings.db = crate::settings_ui::DbStatus::read(app.settings.db_path.as_deref());
        dir
    }

    #[test]
    fn ticking_vulns_without_cve_data_points_to_settings() {
        let (_rt, mut app) = app();
        let _dir = cve_data(&mut app, false);
        app.form.focus = Field::Vulns;
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.vuln_popup, Some(true), "Services was off");
        let screen = render(&mut app, 90, 30);
        assert!(
            screen.contains("CVE data hasn't been set up yet"),
            "{screen}"
        );
        assert!(screen.contains("Services was turned on too"), "{screen}");

        // Other keys don't fall through to the form; Esc keeps Vulns ticked.
        press(&mut app, KeyCode::Char(' '));
        assert!(app.vuln_popup.is_some() && app.form.vuln_matching);
        press(&mut app, KeyCode::Esc);
        assert!(app.vuln_popup.is_none() && !app.settings.is_open());
        assert!(app.form.vuln_matching && app.form.service_detection);
        assert!(matches!(app.screen, Screen::Setup) && !app.should_quit());

        // Unticking is quiet; ticking again asks again, now without the
        // Services line, and Enter opens Settings.
        press(&mut app, KeyCode::Char(' '));
        assert!(app.vuln_popup.is_none() && !app.form.vuln_matching);
        press(&mut app, KeyCode::Right);
        assert_eq!(app.vuln_popup, Some(false));
        assert!(!render(&mut app, 90, 30).contains("Services was turned on"));
        press(&mut app, KeyCode::Enter);
        assert!(app.vuln_popup.is_none() && app.settings.is_open());
        assert!(app.form.vuln_matching);
    }

    #[test]
    fn f2_from_the_vuln_popup_opens_settings() {
        let (_rt, mut app) = app();
        let dir = cve_data(&mut app, false);
        // A file that isn't a CVE database counts as no data.
        std::fs::write(dir.0.join("vulns.db"), b"not sqlite").unwrap();
        app.form.focus = Field::Vulns;
        press(&mut app, KeyCode::Char(' '));
        assert!(app.vuln_popup.is_some());
        press(&mut app, KeyCode::F(2));
        assert!(app.vuln_popup.is_none() && app.settings.is_open());
    }

    #[test]
    fn no_vuln_popup_when_cve_data_exists() {
        let (_rt, mut app) = app();
        let _dir = cve_data(&mut app, true);
        app.form.focus = Field::Vulns;
        press(&mut app, KeyCode::Char(' '));
        assert!(app.form.vuln_matching && app.vuln_popup.is_none());
    }

    #[test]
    fn a_profile_that_turns_vulns_on_shows_the_vuln_popup() {
        let (_rt, mut app) = app();
        let _dir = cve_data(&mut app, false);
        let ctrl_p = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL);
        app.on_key(ctrl_p);
        press(&mut app, KeyCode::Down); // "Full audit": Services and Vulns
        press(&mut app, KeyCode::Enter);
        assert!(app.form.vuln_matching && app.profiles.picker.is_none());
        assert_eq!(app.vuln_popup, Some(true));
        press(&mut app, KeyCode::Esc);
        // Re-applying with Vulns already on doesn't ask again.
        app.on_key(ctrl_p);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert!(app.vuln_popup.is_none());
    }

    #[test]
    fn vuln_popup_fits_tiny_terminals() {
        let (_rt, mut app) = app();
        app.vuln_popup = Some(true);
        for (w, h) in [(1, 1), (8, 3), (20, 6), (40, 10), (61, 14)] {
            render(&mut app, w, h);
        }
    }
}
