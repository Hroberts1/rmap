//! Re-scan one host from the results screen (`r`).
//!
//! The rescan is a second engine [`Scan`] over every port (1-65535) of the
//! selected host, with service detection and CVE matching on and the
//! original scan's type and timing. It only starts once the main scan has
//! ended, and only one runs at a time.
//!
//! Its events go into a scratch [`ReportBuilder`], not the view. When it
//! finishes, the host is replaced in one go by replaying the result through
//! `ScanView::apply`, which updates the live view and the scan's report
//! alike. A rescan that is stopped (`s`) or dies leaves the earlier results
//! as they were, so a partial pass never hides ports the first scan found.
//!
//! After the merge the scan is auto-saved again as a new file: the store
//! never overwrites, and the pre-rescan file stays as a baseline for `c`.

use std::iter;
use std::net::IpAddr;
use std::time::Duration;

use rmap_core::{HostState, PortList, ScanEvent, Target, Timing};
use rmap_engine::{Scan, ScanConfig};
use rmap_report::{ConfigSummary, ReportBuilder, unix_millis_now};
use tokio::sync::mpsc::error::TryRecvError;

use crate::app::{App, EVENTS_PER_FRAME, ScanView, WARNING_PREFIX};

/// A rescan in progress.
pub struct Rescan {
    pub ip: IpAddr,
    pub scan: Scan,
    report: ReportBuilder,
}

/// Every port of `ip`, keeping the original scan type and timing.
fn rescan_config(ip: IpAddr, original: &ConfigSummary) -> ScanConfig {
    let target = match ip {
        IpAddr::V4(a) => Target::V4Range { start: a, end: a },
        IpAddr::V6(a) => Target::V6Range { start: a, end: a },
    };
    ScanConfig {
        targets: vec![target],
        ports: PortList::parse("1-65535").expect("valid port range"),
        timing: Timing::template(original.timing_level),
        // The host was already seen; probing it again could only skip it.
        discovery: false,
        scan_type: original.scan_type,
        service_detection: true,
        vuln_matching: true,
        // The host was in scope; keep the original rate cap so a rescan of a
        // fragile device is no harder on it than the first pass.
        exclude: Vec::new(),
        max_rate: original.max_rate,
        resolve_names: original.resolve_names,
        dns_server: original.dns_server,
        vuln_db: None,
    }
}

impl App {
    /// `r`: rescan the selected host, asking first if it may be public.
    pub(crate) fn request_rescan(&mut self) {
        let Some(view) = self.scan.as_mut() else {
            return;
        };
        let Some(ip) = view.selected else {
            view.log("select a host to rescan".into());
            return;
        };
        if view.is_running() {
            view.log("wait for the scan to finish, or stop it (s), before rescanning".into());
            return;
        }
        if let Some(r) = &view.rescan {
            view.log(format!("already rescanning {}", r.ip));
            return;
        }
        let config = rescan_config(ip, &view.report.report().config);
        if config.targets[0].may_be_public() {
            rmap_log::info!("asking to confirm rescan of public address {ip}");
            self.pending = Some((config, vec![ip.to_string()]));
        } else {
            self.start_rescan(config);
        }
    }

    /// Start a rescan built by `rescan_config`.
    pub(crate) fn start_rescan(&mut self, config: ScanConfig) {
        let Some(view) = self.scan.as_mut() else {
            return;
        };
        let Some(ip) = config.targets.first().and_then(|t| t.addrs().next()) else {
            return;
        };
        let summary = crate::report::config_summary(&ip.to_string(), "", &config);
        view.log(format!(
            "rescanning {ip}: {} ports, {} scan, T{}, services and CVEs",
            config.ports.len(),
            config.scan_type.label(),
            config.timing.level,
        ));
        view.rescan = Some(Rescan {
            ip,
            scan: Scan::start(&self.rt, config),
            report: ReportBuilder::new(summary, unix_millis_now()),
        });
    }
}

impl ScanView {
    /// `s` while a rescan runs: drop it and keep the earlier results.
    pub(crate) fn stop_rescan(&mut self) {
        if let Some(r) = self.rescan.take() {
            r.scan.stop();
            self.log(format!(
                "rescan of {} stopped; kept the earlier results",
                r.ip
            ));
        }
    }

    /// Pull the rescan's events; merge its result once it finishes.
    pub(crate) fn drain_rescan(&mut self) {
        let Some(mut r) = self.rescan.take() else {
            return;
        };
        for _ in 0..EVENTS_PER_FRAME {
            match r.scan.events.try_recv() {
                Ok(ScanEvent::Finished { elapsed }) => {
                    self.merge_rescan(&r, elapsed);
                    return;
                }
                Ok(ScanEvent::Warning(msg)) => self.log(format!("{WARNING_PREFIX}{msg}")),
                Ok(event) => r.report.apply(&event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    rmap_log::error!("rescan of {} stopped without finishing", r.ip);
                    self.log(format!(
                        "rescan of {} stopped unexpectedly; kept the earlier results",
                        r.ip
                    ));
                    return;
                }
            }
        }
        self.rescan = Some(r);
    }

    fn merge_rescan(&mut self, r: &Rescan, elapsed: Duration) {
        let ip = r.ip;
        let report = r.report.report();
        let Some(new) = report.host(ip) else {
            rmap_log::warn!("rescan of {ip} finished without reporting the host");
            self.log(format!(
                "rescan of {ip} returned nothing; kept the earlier results"
            ));
            return;
        };
        let old = self.hosts.get(&ip);
        // Discovery is off for the rescan, so its state is only "assumed";
        // keep what the first scan learned unless that was "down".
        let state = match old.map(|h| h.state) {
            Some(s) if s != HostState::Down => s,
            _ => new.state,
        };
        let host = ScanEvent::Host {
            ip,
            hostname: new
                .hostname
                .clone()
                .or_else(|| old.and_then(|h| h.hostname.clone())),
            state,
            rtt: new.rtt.or_else(|| old.and_then(|h| h.rtt)),
        };
        let ports = new.ports.iter().map(|p| ScanEvent::Port {
            ip,
            result: p.clone(),
        });
        let done = ScanEvent::HostDone {
            ip,
            closed: new.closed,
            filtered: new.filtered,
            elapsed,
        };
        // Host resets the row (and the report's host); Port and HostDone
        // refill it. Service and CVE data ride along inside each PortResult.
        for event in iter::once(host).chain(ports).chain(iter::once(done)) {
            self.apply(event);
        }
        if self.selected == Some(ip) {
            self.port_selected = self.port_selected.min(new.ports.len().saturating_sub(1));
        }
        let line = format!(
            "rescan of {ip} finished: {} open ports in {:.1}s",
            new.ports.len(),
            elapsed.as_secs_f64()
        );
        rmap_log::info!("{line}");
        self.log(line);
        // Save the merged scan again; the store writes a new file.
        self.save_attempted = false;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rmap_core::{PortResult, PortState, Protocol, ScanType};
    use rmap_report::ScanStore;

    use super::*;
    use crate::app::Screen;

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(w.max(1) as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect()
    }

    fn wait_for(app: &mut App, what: &str, done: impl Fn(&App) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done(app) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            app.drain_events();
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn listen(rt: &tokio::runtime::Runtime) -> u16 {
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        rt.spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        port
    }

    /// A finished T5 connect scan of `ports` on 127.0.0.1.
    fn scanned(rt: &tokio::runtime::Runtime, ports: &str) -> App {
        let mut app = App::new(rt.handle().clone());
        app.form.targets = "127.0.0.1".into();
        app.form.ports = ports.into();
        app.form.discovery = false;
        app.form.timing = 5;
        press(&mut app, KeyCode::Enter);
        wait_for(&mut app, "main scan", |a| {
            a.scan.as_ref().unwrap().finished.is_some()
        });
        app
    }

    fn localhost() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn config_covers_every_port_and_keeps_type_and_timing() {
        let summary = ConfigSummary {
            targets: "10.0.0.0/24".into(),
            ports: "22".into(),
            port_count: 1,
            scan_type: ScanType::Udp,
            timing_level: 4,
            timing_name: "aggressive".into(),
            discovery: true,
            service_detection: false,
            exclude: String::new(),
            max_rate: Some(50),
            resolve_names: true,
            dns_server: Some("10.0.0.10".parse().unwrap()),
        };
        let c = rescan_config("10.0.0.7".parse().unwrap(), &summary);
        assert_eq!(c.ports.len(), 65_535);
        assert_eq!((c.scan_type, c.timing.level), (ScanType::Udp, 4));
        assert!(c.service_detection && c.vuln_matching && !c.discovery);
        assert_eq!(c.max_rate, Some(50));
        assert!(c.resolve_names);
        assert_eq!(c.dns_server, Some("10.0.0.10".parse().unwrap()));
        assert_eq!(c.targets[0].to_string(), "10.0.0.7");
        let c = rescan_config("::1".parse().unwrap(), &summary);
        assert_eq!(
            c.targets[0].addrs().collect::<Vec<_>>(),
            ["::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn refused_while_the_main_scan_runs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.form.targets = "192.0.2.1".into();
        app.form.ports = "1-1000".into();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('y'));
        let view = app.scan.as_mut().unwrap();
        view.apply(ScanEvent::Host {
            ip: "192.0.2.1".parse().unwrap(),
            hostname: None,
            state: HostState::Assumed,
            rtt: None,
        });
        press(&mut app, KeyCode::Char('r'));
        let view = app.scan.as_ref().unwrap();
        assert!(view.rescan.is_none() && app.pending.is_none());
        assert!(view.log.back().unwrap().contains("before rescanning"));
    }

    #[test]
    fn public_host_asks_first() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.form.targets = "192.0.2.1".into(); // TEST-NET, counted as public
        app.form.ports = "80".into();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('y'));
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        view.apply(ScanEvent::Host {
            ip: "192.0.2.1".parse().unwrap(),
            hostname: None,
            state: HostState::Assumed,
            rtt: None,
        });
        press(&mut app, KeyCode::Char('r'));
        assert!(app.pending.is_some());
        assert!(render(&mut app, 80, 24).contains("public addresses"));
        press(&mut app, KeyCode::Char('n'));
        assert!(app.scan.as_ref().unwrap().rescan.is_none());

        press(&mut app, KeyCode::Char('r'));
        press(&mut app, KeyCode::Char('y'));
        assert!(matches!(app.screen, Screen::Results));
        let view = app.scan.as_ref().unwrap();
        assert!(view.rescan.is_some(), "the rescan, not a new scan, starts");
        assert!(view.stopped, "the original view is kept");
        let screen = render(&mut app, 80, 24);
        let header = screen.lines().next().unwrap();
        assert!(header.contains("rescanning"), "{screen}");
        // Stopping drops it and keeps the old row.
        press(&mut app, KeyCode::Char('s'));
        let view = app.scan.as_ref().unwrap();
        assert!(view.rescan.is_none());
        assert!(
            view.log
                .back()
                .unwrap()
                .contains("kept the earlier results")
        );
        assert!(view.hosts.contains_key(&"192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn rescan_of_localhost_merges_and_saves_again() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (a, b) = (listen(&rt), listen(&rt));
        // The first scan only sees `a`.
        let mut app = scanned(&rt, &a.to_string());
        let tmp = std::env::temp_dir().join(format!("rmap-rescan-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        app.store = Some(ScanStore::new(tmp.clone()));
        app.scan.as_mut().unwrap().save_attempted = false;
        app.drain_events();
        let first_save = app.scan.as_ref().unwrap().saved.clone().unwrap();
        assert_eq!(app.scan.as_ref().unwrap().selected, Some(localhost()));

        // A real rescan covers all 65,535 ports; on Windows refused loopback
        // connects are slow, so drive the same path with a short list.
        let mut config = rescan_config(
            localhost(),
            &app.scan.as_ref().unwrap().report.report().config,
        );
        config.ports = PortList::parse(&format!("{a},{b}")).unwrap();
        app.start_rescan(config);
        for (w, h) in [(80, 24), (120, 32)] {
            let screen = render(&mut app, w, h);
            let header = screen.lines().next().unwrap();
            assert!(header.contains("rescanning"), "{w}x{h}:\n{screen}");
            assert!(screen.contains('↻'), "host row marked:\n{screen}");
        }
        press(&mut app, KeyCode::Char('r'));
        assert!(
            app.scan
                .as_ref()
                .unwrap()
                .log
                .back()
                .unwrap()
                .contains("already rescanning")
        );

        wait_for(&mut app, "rescan", |a| {
            a.scan.as_ref().unwrap().rescan.is_none()
        });
        let view = app.scan.as_ref().unwrap();
        let ports: Vec<u16> = view.hosts[&localhost()]
            .open
            .iter()
            .map(|p| p.port)
            .collect();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(ports, want);
        assert!(
            view.log
                .iter()
                .any(|l| l.contains("rescan of 127.0.0.1 finished"))
        );
        let report = view.report.report();
        assert_eq!(
            report.host(localhost()).unwrap().ports.len(),
            2,
            "report updated"
        );
        let second_save = view.saved.clone().unwrap();
        assert_ne!(first_save, second_save, "saved as a new file");
        assert!(first_save.exists() && second_save.exists());

        let screen = render(&mut app, 120, 32);
        assert!(screen.contains(&format!("{b}/tcp")), "{screen}");
        assert!(!screen.contains('↻'), "{screen}");
        render(&mut app, 20, 6);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stopped_rescan_keeps_earlier_ports() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let port = listen(&rt);
        let mut app = scanned(&rt, &port.to_string());
        press(&mut app, KeyCode::Char('r'));
        let view = app.scan.as_ref().unwrap();
        assert!(view.rescan.is_some());
        assert!(
            view.log.back().unwrap().contains("65535 ports"),
            "{:?}",
            view.log
        );
        press(&mut app, KeyCode::Char('s'));
        app.drain_events();
        let view = app.scan.as_ref().unwrap();
        assert!(view.rescan.is_none() && !view.failed);
        assert_eq!(view.hosts[&localhost()].open.len(), 1);
    }

    #[test]
    fn merge_replaces_the_host_row() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = scanned(&rt, "9");
        let view = app.scan.as_mut().unwrap();
        let ip = localhost();
        view.apply(ScanEvent::Port {
            ip,
            result: PortResult::new(22, Protocol::Tcp, PortState::Open, None),
        });
        view.port_selected = 0;
        // A finished rescan that found only 80, with a service.
        let mut report = ReportBuilder::new(view.report.report().config, 0);
        report.apply(&ScanEvent::Host {
            ip,
            hostname: Some("me".into()),
            state: HostState::Assumed,
            rtt: None,
        });
        let mut result = PortResult::new(80, Protocol::Tcp, PortState::Open, None);
        result.service = Some(rmap_core::Service {
            name: "http".into(),
            ..Default::default()
        });
        report.apply(&ScanEvent::Port { ip, result });
        let r = Rescan {
            ip,
            scan: Scan::start(rt.handle(), rescan_config(ip, &view.report.report().config)),
            report,
        };
        r.scan.stop();
        view.merge_rescan(&r, Duration::from_secs(1));
        let host = &view.hosts[&ip];
        assert_eq!(host.open.len(), 1);
        assert_eq!(host.open[0].port, 80);
        assert_eq!(host.open[0].service.as_ref().unwrap().name, "http");
        assert_eq!(host.hostname.as_deref(), Some("me"));
        assert!(host.done);
        let saved = view.report.report();
        assert_eq!(saved.host(ip).unwrap().ports[0].port, 80);
    }
}
