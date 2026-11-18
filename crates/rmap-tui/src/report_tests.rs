//! Tests for the export dialog, auto-save, the saved-scan picker and the
//! diff screen. Every test saves into its own temp directory.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use rmap_core::{HostState, PortResult, PortState, Protocol, ScanEvent, Service};
use rmap_report::{ReportBuilder, RunStatus, ScanStore};

use super::*;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmap-tui-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn ctrl(app: &mut App, c: char) {
    app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
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

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn ssh(version: &str) -> Service {
    Service {
        name: "ssh".into(),
        product: Some("OpenSSH".into()),
        version: Some(version.into()),
        ..Default::default()
    }
}

fn export_dialog(app: &App) -> &ExportDialog {
    match &app.dialog {
        Some(Dialog::Export(d)) => d,
        _ => panic!("no export dialog"),
    }
}

fn picker(app: &App) -> &ComparePicker {
    match &app.dialog {
        Some(Dialog::Compare(p)) => p,
        _ => panic!("no picker: {:?}", app.scan.as_ref().map(|v| &v.log)),
    }
}

/// An app on the results screen of a stopped scan of `targets`, fed
/// synthetic events, saving into `tmp`.
fn stopped_scan(tmp: &TempDir, targets: &str, ssh_version: &str) -> (tokio::runtime::Runtime, App) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut app = App::new(rt.handle().clone());
    app.store = Some(ScanStore::new(tmp.0.join("scans")));
    app.form.targets = targets.into();
    app.form.ports = "9".into();
    app.form.discovery = false;
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.screen, Screen::Results));
    let view = app.scan.as_mut().unwrap();
    view.scan.stop();
    view.stopped = true;
    let host = ip("10.0.0.2");
    view.apply(ScanEvent::Host {
        ip: host,
        hostname: None,
        state: HostState::Up,
        rtt: None,
    });
    view.apply(ScanEvent::Port {
        ip: host,
        result: PortResult::new(22, Protocol::Tcp, PortState::Open, None),
    });
    view.apply(ScanEvent::Service {
        ip: host,
        protocol: Protocol::Tcp,
        port: 22,
        service: ssh(ssh_version),
    });
    (rt, app)
}

fn drain_until_saved(app: &mut App) -> PathBuf {
    for _ in 0..500 {
        app.drain_events();
        if let Some(p) = &app.scan.as_ref().unwrap().saved {
            return p.clone();
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("scan was not saved: {:?}", app.scan.as_ref().unwrap().log);
}

#[test]
fn stopped_scan_is_saved_once() {
    let tmp = TempDir::new();
    let (_rt, mut app) = stopped_scan(&tmp, "127.0.0.1", "9.6");
    let path = drain_until_saved(&mut app);
    let saved = ScanStore::load(&path).unwrap();
    assert_eq!(saved.status, RunStatus::Stopped);
    assert_eq!(saved.config.targets, "127.0.0.1");
    assert_eq!(saved.hosts[0].ports[0].service, Some(ssh("9.6")));
    let view = app.scan.as_ref().unwrap();
    assert!(view.log.iter().any(|l| l.starts_with("saved to ")));
    app.drain_events();
    assert_eq!(
        ScanStore::new(tmp.0.join("scans")).list().0.len(),
        1,
        "saved once"
    );
    assert!(render(&mut app, 120, 30).contains("saved to"));
}

#[test]
fn save_failure_is_reported_in_the_log() {
    let tmp = TempDir::new();
    let (_rt, mut app) = stopped_scan(&tmp, "127.0.0.1", "9.6");
    let blocker = tmp.0.join("file");
    std::fs::write(&blocker, "x").unwrap();
    app.store = Some(ScanStore::new(blocker.join("scans")));
    app.drain_events();
    let view = app.scan.as_ref().unwrap();
    assert!(view.saved.is_none() && view.save_attempted);
    assert!(
        view.log
            .iter()
            .any(|l| l.starts_with("could not save scan"))
    );
}

#[test]
fn export_dialog_writes_json_and_xml() {
    let tmp = TempDir::new();
    let (_rt, mut app) = stopped_scan(&tmp, "127.0.0.1", "9.6");
    press(&mut app, KeyCode::Char('e'));
    let d = export_dialog(&app);
    assert_eq!(d.format, ExportFormat::Json);
    assert!(d.path.ends_with(".json"));
    assert!(Path::new(&d.path).starts_with(tmp.0.join("scans").join("exports")));
    assert!(render(&mut app, 100, 30).contains("export"));

    press(&mut app, KeyCode::Char('d')); // typed into the path, not "toggle down hosts"
    assert!(!app.scan.as_ref().unwrap().show_down);
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Enter);
    let d = export_dialog(&app);
    assert_eq!(d.status, Some(Ok(d.path.clone())));
    let back = rmap_report::json::from_str(&std::fs::read_to_string(&d.path).unwrap());
    assert_eq!(back.unwrap().hosts[0].ports[0].port, 22);
    assert!(render(&mut app, 100, 30).contains("✓ saved to"));

    press(&mut app, KeyCode::Tab);
    let d = export_dialog(&app);
    assert_eq!(d.format, ExportFormat::Xml);
    assert!(d.path.ends_with(".xml") && d.status.is_none());
    press(&mut app, KeyCode::Enter);
    let xml = std::fs::read_to_string(&export_dialog(&app).path).unwrap();
    assert!(
        xml.contains("<port protocol=\"tcp\" portid=\"22\">"),
        "{xml}"
    );
    assert!(xml.contains("product=\"OpenSSH\" version=\"9.6\""));
    for _ in 0..3 {
        press(&mut app, KeyCode::Tab);
    }
    let d = export_dialog(&app);
    assert_eq!(d.format, ExportFormat::Html);
    assert!(d.path.ends_with(".html"));
    // All five formats fit on the dialog's format line at 80x24.
    let screen = render(&mut app, 80, 24);
    assert!(
        screen.contains("Markdown") && screen.contains("HTML"),
        "{screen}"
    );
    render(&mut app, 20, 6); // tiny terminals must not panic
    press(&mut app, KeyCode::Enter);
    let html = std::fs::read_to_string(&export_dialog(&app).path).unwrap();
    assert!(
        html.contains("<td>22/tcp</td>") && html.contains("OpenSSH 9.6"),
        "{html}"
    );

    // A path that can't be written shows the error inline.
    ctrl(&mut app, 'u');
    type_text(&mut app, &tmp.0.display().to_string());
    press(&mut app, KeyCode::Enter);
    assert!(matches!(&export_dialog(&app).status, Some(Err(_))));
    assert!(render(&mut app, 100, 30).contains("✗"));
    ctrl(&mut app, 'u');
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        export_dialog(&app).status,
        Some(Err("enter a file path".into()))
    );

    for (w, h) in [(20, 6), (1, 1), (0, 0), (300, 3)] {
        render(&mut app, w, h);
    }
    press(&mut app, KeyCode::Esc);
    assert!(app.dialog.is_none());
    assert!(
        matches!(app.screen, Screen::Results),
        "Esc only closes the dialog"
    );
    let log = &app.scan.as_ref().unwrap().log;
    assert!(log.iter().any(|l| l.starts_with("exported JSON")));
    assert!(log.iter().any(|l| l.starts_with("export failed")));
}

#[test]
fn compare_picks_same_targets_and_shows_the_diff() {
    let tmp = TempDir::new();
    let store = ScanStore::new(tmp.0.join("scans"));
    let config = |targets: &str| {
        let (_rt, app) = stopped_scan(&tmp, targets, "8.9");
        app.scan.as_ref().unwrap().report.report().config
    };
    // Two earlier scans: the same targets (older) and other targets (newer).
    let mut same = ReportBuilder::new(config("127.0.0.1"), 1_000);
    let host = ip("10.0.0.2");
    same.apply(&ScanEvent::Host {
        ip: host,
        hostname: None,
        state: HostState::Up,
        rtt: None,
    });
    for port in [22, 23] {
        same.apply(&ScanEvent::Port {
            ip: host,
            result: PortResult::new(port, Protocol::Tcp, PortState::Open, None),
        });
    }
    same.apply(&ScanEvent::Service {
        ip: host,
        protocol: Protocol::Tcp,
        port: 22,
        service: ssh("8.9"),
    });
    same.mark_stopped(2_000);
    store.save(&same.report()).unwrap();
    store
        .save(&ReportBuilder::new(config("127.0.0.9"), 5_000).report())
        .unwrap();

    let (_rt, mut app) = stopped_scan(&tmp, "127.0.0.1", "9.6");
    let own = drain_until_saved(&mut app);
    press(&mut app, KeyCode::Char('c'));
    let p = picker(&app);
    assert_eq!(p.scans.len(), 2, "the current scan isn't offered");
    assert!(p.scans.iter().all(|s| s.path != own));
    assert_eq!(p.scans[p.selected].report.config.targets, "127.0.0.1");
    let selected = p.selected;
    assert!(render(&mut app, 100, 30).contains("compare with a saved scan"));
    for (w, h) in [(20, 6), (1, 1), (0, 0)] {
        render(&mut app, w, h);
    }

    // Navigation is clamped.
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Down);
    assert_eq!(picker(&app).selected, 1);
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Up);
    assert_eq!(picker(&app).selected, 0);
    for _ in 0..selected {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert!(app.dialog.is_none());
    assert!(matches!(app.screen, Screen::Diff));

    let diff = app.diff.as_ref().unwrap();
    let text: Vec<&str> = diff.lines.iter().map(|l| l.text.as_str()).collect();
    assert!(text.contains(&"- 10.0.0.2 23/tcp  open"), "{text:?}");
    assert!(
        text.contains(&"~ 10.0.0.2 22/tcp  ssh (OpenSSH 8.9) → ssh (OpenSSH 9.6)"),
        "{text:?}"
    );
    assert_eq!(diff.changes, 2);
    let screen = render(&mut app, 100, 30);
    assert!(
        screen.contains("2 changes") && screen.contains("OpenSSH 9.6"),
        "{screen}"
    );

    // Scrolling stops at the ends.
    let last = app.diff.as_ref().unwrap().lines.len() - 1;
    for _ in 0..50 {
        press(&mut app, KeyCode::PageDown);
    }
    assert_eq!(app.diff.as_ref().unwrap().scroll, last);
    press(&mut app, KeyCode::Up);
    assert_eq!(app.diff.as_ref().unwrap().scroll, last.saturating_sub(1));
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Up);
    assert_eq!(app.diff.as_ref().unwrap().scroll, 0);
    for (w, h) in [(20, 6), (1, 1), (0, 0), (300, 2)] {
        render(&mut app, w, h);
    }

    press(&mut app, KeyCode::Esc);
    assert!(matches!(app.screen, Screen::Results) && app.diff.is_none());
    assert!(!app.should_quit());
}

#[test]
fn compare_needs_a_finished_scan_and_another_saved_one() {
    let tmp = TempDir::new();
    let (_rt, mut app) = stopped_scan(&tmp, "127.0.0.1", "9.6");
    drain_until_saved(&mut app);
    press(&mut app, KeyCode::Char('c'));
    assert!(app.dialog.is_none());
    let log = &app.scan.as_ref().unwrap().log;
    assert!(
        log.last().unwrap().starts_with("no other saved scans"),
        "{log:?}"
    );

    app.store = None; // saving disabled
    press(&mut app, KeyCode::Char('c'));
    assert!(app.dialog.is_none());

    // Looks like it's still running: is_running() needs both fields reset,
    // since the real engine's cancellation can independently have set
    // `finished` already (it ran for real in `stopped_scan`, just stopped).
    {
        let view = app.scan.as_mut().unwrap();
        view.stopped = false;
        view.finished = None;
    }
    press(&mut app, KeyCode::Char('c'));
    assert!(app.dialog.is_none());
    let log = &app.scan.as_ref().unwrap().log;
    assert!(log.last().unwrap().contains("before comparing"), "{log:?}");
}

#[test]
fn empty_diff_screen_renders_and_quits() {
    let tmp = TempDir::new();
    let (_rt, mut app) = stopped_scan(&tmp, "127.0.0.1", "9.6");
    app.diff = Some(DiffView {
        old: "a".into(),
        new: "b".into(),
        changes: 0,
        lines: Vec::new(),
        scroll: 0,
    });
    app.screen = Screen::Diff;
    assert!(render(&mut app, 80, 24).contains("0 changes"));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::End);
    assert_eq!(app.diff.as_ref().unwrap().scroll, 0);
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit());
}

#[test]
fn shutdown_saves_a_running_scan_as_stopped() {
    let tmp = TempDir::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut app = App::new(rt.handle().clone());
    app.store = Some(ScanStore::new(tmp.0.join("scans")));
    app.form.targets = "192.0.2.1".into(); // never routed
    app.form.ports = "1-1000".into();
    app.form.discovery = false;
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('y'));
    assert!(app.scan.as_ref().unwrap().is_running());
    app.shutdown();
    let path = app.scan.as_ref().unwrap().saved.clone().unwrap();
    assert_eq!(ScanStore::load(&path).unwrap().status, RunStatus::Stopped);
}

#[test]
fn export_toggle_swaps_only_matching_extensions() {
    let mut d = ExportDialog {
        format: ExportFormat::Json,
        path: "out.JSON".into(),
        status: None,
    };
    d.toggle_format();
    assert_eq!((d.format, d.path.as_str()), (ExportFormat::Xml, "out.xml"));
    for (format, path) in [
        (ExportFormat::Markdown, "out.md"),
        (ExportFormat::Csv, "out.csv"),
        (ExportFormat::Html, "out.html"),
        (ExportFormat::Json, "out.json"),
    ] {
        d.toggle_format();
        assert_eq!((d.format, d.path.as_str()), (format, path));
    }
    d.path = "report.txt".into();
    d.toggle_format();
    assert_eq!(
        (d.format, d.path.as_str()),
        (ExportFormat::Xml, "report.txt")
    );
    d.path.clear();
    d.toggle_format();
    assert_eq!(d.path, "");
}

#[test]
fn long_paths_show_their_tail() {
    assert_eq!(crate::report_ui::tail("abcdef", 10), "abcdef");
    assert_eq!(crate::report_ui::tail("abcdef", 4), "…def");
    assert_eq!(crate::report_ui::tail("ééééé", 2), "…é");
    assert_eq!(crate::report_ui::tail("abc", 0), "…");
}
