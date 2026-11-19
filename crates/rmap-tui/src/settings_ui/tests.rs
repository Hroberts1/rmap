use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

use super::*;
use crate::settings::TempDir;

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

fn app() -> (tokio::runtime::Runtime, App) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let app = App::new(rt.handle().clone());
    (rt, app)
}

fn manifest(built_at: &str) -> Manifest {
    Manifest {
        schema_version: rmap_vuln::SCHEMA_VERSION,
        built_at: built_at.into(),
        cve_count: 12_345,
        source: "test".into(),
        size: 4_200_000,
        sha256: [0; 32],
        db_url: "https://github.com/example/vulns.db".into(),
    }
}

/// A real (empty) database file built on `built_at`.
fn write_db(path: &Path, built_at: &str) -> DbInfo {
    let part = path.with_extension("db.fake");
    let _ = std::fs::remove_file(&part);
    let mut w = rmap_vuln::Writer::create(&part).unwrap();
    w.set_meta("built_at", built_at).unwrap();
    w.set_meta("source", "test").unwrap();
    w.finish().unwrap();
    std::fs::rename(&part, path).unwrap();
    rmap_vuln::Database::open(path).unwrap().info().clone()
}

/// Points the app at a CVE data file and settings file in `dir`.
fn use_dir(app: &mut App, dir: &TempDir, updater: Updater) {
    let s = &mut app.settings;
    s.path = Some(dir.0.join("settings.json"));
    s.db_path = Some(dir.0.join("vulns.db"));
    s.db = DbStatus::read(s.db_path.as_deref());
    s.updater = updater;
}

/// Polls until no check or download is running.
fn settle(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while matches!(
        app.settings.job,
        Job::Checking { .. } | Job::Installing { .. }
    ) || app.settings.startup.is_some()
    {
        assert!(Instant::now() < deadline, "update job did not finish");
        app.drain_events();
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn message(app: &App) -> String {
    let sc = app.settings.screen.as_ref().unwrap();
    sc.message.as_ref().map(|m| m.0.clone()).unwrap_or_default()
}

fn fake_results(app: &mut App) {
    app.form.targets = "127.0.0.1".into();
    app.form.ports = "9".into();
    app.form.discovery = false;
    press(app, KeyCode::Enter);
    let view = app.scan.as_mut().unwrap();
    view.scan.stop();
    view.stopped = true;
}

fn fetch_new(_: &str) -> Result<Manifest, UpdateError> {
    Ok(manifest("2026-11-15T00:00:00Z"))
}
fn fetch_old(_: &str) -> Result<Manifest, UpdateError> {
    Ok(manifest("2026-10-01T00:00:00Z"))
}
fn fetch_same(_: &str) -> Result<Manifest, UpdateError> {
    Ok(manifest("2026-11-01T00:00:00Z"))
}
fn fetch_404(_: &str) -> Result<Manifest, UpdateError> {
    Err(UpdateError::Http(404))
}
fn fetch_never(_: &str) -> Result<Manifest, UpdateError> {
    panic!("must not contact the network")
}
fn install_ok(
    m: &Manifest,
    dest: &Path,
    progress: &mut dyn FnMut(Progress),
) -> Result<DbInfo, UpdateError> {
    progress(Progress::Downloading {
        done: m.size / 2,
        total: m.size,
    });
    progress(Progress::Verifying);
    progress(Progress::Installing);
    Ok(write_db(dest, &m.built_at))
}
fn install_bad_hash(
    _: &Manifest,
    _: &Path,
    _: &mut dyn FnMut(Progress),
) -> Result<DbInfo, UpdateError> {
    Err(UpdateError::HashMismatch)
}
fn install_never(
    _: &Manifest,
    _: &Path,
    _: &mut dyn FnMut(Progress),
) -> Result<DbInfo, UpdateError> {
    panic!("must not download")
}

#[test]
fn keys_open_and_close_settings() {
    let (_rt, mut app) = app();
    press(&mut app, KeyCode::Char('S'));
    assert_eq!(app.form.targets, "S", "S types into the setup form");
    assert!(!app.settings.is_open());
    press(&mut app, KeyCode::F(2));
    assert!(app.settings.is_open());
    assert!(render(&mut app, 80, 24).contains("rmap · settings"));
    press(&mut app, KeyCode::Char('q'));
    assert!(!app.should_quit(), "keys don't reach the screen underneath");
    press(&mut app, KeyCode::Esc);
    assert!(!app.settings.is_open() && app.confirm.is_none());

    fake_results(&mut app);
    press(&mut app, KeyCode::Char('S'));
    assert!(app.settings.is_open());
    press(&mut app, KeyCode::Esc);
    assert!(!app.settings.is_open());
    assert!(matches!(app.screen, crate::app::Screen::Results));
}

#[test]
fn renders_at_80x24_wide_and_tiny() {
    let dir = TempDir::new("render");
    let (_rt, mut app) = app();
    use_dir(&mut app, &dir, Updater::default());
    press(&mut app, KeyCode::F(2));
    let screen = render(&mut app, 80, 24);
    for needle in [
        "Vulnerability data",
        "vulns.db",
        "not downloaded yet: CVE matching is off until you update",
        "[ Update now ]",
        "https://github.com/",
        "Reset URL to default",
        "[ ] check for updates on startup",
        "contacts the update URL each time rmap starts",
        "30",
        "older than this",
        "[x] mark actively exploited CVEs (CISA KEV)",
        "Esc",
    ] {
        assert!(screen.contains(needle), "{needle}:\n{screen}");
    }
    for line in screen.lines() {
        assert_eq!(line.chars().count(), 80, "{line:?}");
    }
    if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
        println!("{screen}");
    }

    write_db(&dir.0.join("vulns.db"), "2026-11-01T00:00:00Z");
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::F(2));
    let screen = render(&mut app, 120, 40);
    assert!(
        screen.contains("built 2026-11-01 (") && screen.contains("0 CVEs · test"),
        "{screen}"
    );

    // Every job state at awkward sizes.
    let (_tx, rx) = mpsc::channel();
    app.settings.job = Job::Installing {
        rx,
        progress: Some(Progress::Downloading {
            done: 2_100_000,
            total: 4_200_000,
        }),
    };
    assert!(render(&mut app, 80, 24).contains("downloading 2.1 MB of 4.2 MB (50%)"));
    for (w, h) in [(1, 1), (20, 6), (40, 12)] {
        render(&mut app, w, h);
    }
    let m = manifest("2026-11-15T00:00:00Z");
    app.settings.job = Job::Confirm {
        question: question(&m, &app.settings.db),
        manifest: m,
    };
    let screen = render(&mut app, 80, 24);
    assert!(
        screen.contains("4.2 MB") && screen.contains("12,345 CVEs"),
        "{screen}"
    );
    for (w, h) in [(1, 1), (20, 6), (40, 12), (200, 60)] {
        render(&mut app, w, h);
    }
}

#[test]
fn update_now_downloads_after_asking() {
    let dir = TempDir::new("success");
    let (_rt, mut app) = app();
    use_dir(
        &mut app,
        &dir,
        Updater {
            fetch: fetch_new,
            install: install_ok,
        },
    );
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::Enter);
    assert!(render(&mut app, 80, 24).contains("checking github.com…"));
    settle(&mut app);
    assert!(matches!(app.settings.job, Job::Confirm { .. }));
    let Job::Confirm { question, .. } = &app.settings.job else {
        unreachable!()
    };
    assert_eq!(
        question,
        "Download 4.2 MB of CVE data built 2026-11-15 (12,345 CVEs) from github.com?"
    );
    press(&mut app, KeyCode::Char('x'));
    assert!(
        matches!(app.settings.job, Job::Confirm { .. }),
        "only y/n answer"
    );
    press(&mut app, KeyCode::Char('y'));
    assert!(matches!(app.settings.job, Job::Installing { .. }));
    settle(&mut app);
    let (notice, error) = app.settings.notice.clone().unwrap();
    assert_eq!(notice, "CVE data updated: built 2026-11-15, 0 CVEs");
    assert!(!error);
    assert!(matches!(&app.settings.db, DbStatus::Ready(i) if i.built_at.starts_with("2026-11-15")));
    assert!(render(&mut app, 80, 24).contains("✓ CVE data updated"));
}

#[test]
fn failures_are_reported_in_the_screen_and_log() {
    let dir = TempDir::new("failure");
    let (_rt, mut app) = app();
    fake_results(&mut app);
    use_dir(
        &mut app,
        &dir,
        Updater {
            fetch: fetch_404,
            install: install_never,
        },
    );
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Enter);
    settle(&mut app);
    let (notice, error) = app.settings.notice.clone().unwrap();
    assert!(error && notice.contains("HTTP 404"), "{notice}");
    assert!(render(&mut app, 80, 24).contains("✗ CVE data update check failed"));

    app.settings.updater = Updater {
        fetch: fetch_new,
        install: install_bad_hash,
    };
    press(&mut app, KeyCode::Enter);
    settle(&mut app);
    press(&mut app, KeyCode::Char('y'));
    settle(&mut app);
    let (notice, _) = app.settings.notice.clone().unwrap();
    assert!(notice.contains("SHA-256"), "{notice}");
    assert_eq!(app.settings.db, DbStatus::Missing, "nothing installed");
    let log = &app.scan.as_ref().unwrap().log;
    assert!(
        log.iter()
            .any(|l| l.starts_with(WARNING_PREFIX) && l.contains("SHA-256")),
        "{log:?}"
    );
}

#[test]
fn older_or_same_data_is_called_out_and_n_declines() {
    let dir = TempDir::new("rollback");
    let (_rt, mut app) = app();
    write_db(&dir.0.join("vulns.db"), "2026-11-01T00:00:00Z");
    use_dir(
        &mut app,
        &dir,
        Updater {
            fetch: fetch_old,
            install: install_never,
        },
    );
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::Enter);
    settle(&mut app);
    let screen = render(&mut app, 80, 24);
    assert!(
        screen.contains("OLDER than the data you have") && screen.contains("(2026-11-01)"),
        "{screen}"
    );
    press(&mut app, KeyCode::Char('n'));
    assert!(matches!(app.settings.job, Job::Idle));
    assert_eq!(message(&app), "download cancelled");
    assert!(
        app.settings.is_open(),
        "n answers the question, not the screen"
    );

    app.settings.updater.fetch = fetch_same;
    press(&mut app, KeyCode::Enter);
    settle(&mut app);
    let Job::Confirm { question, .. } = &app.settings.job else {
        panic!("expected a question")
    };
    assert!(question.starts_with("You already have this data (built 2026-11-01)"));
    press(&mut app, KeyCode::Esc);
    assert!(matches!(app.settings.job, Job::Idle));
    assert!(matches!(&app.settings.db, DbStatus::Ready(i) if i.built_at.starts_with("2026-11-01")));
}

#[test]
fn update_is_refused_while_a_scan_runs() {
    let dir = TempDir::new("busy");
    let (_rt, mut app) = app();
    app.form.targets = "192.0.2.1".into();
    app.form.ports = "1-1000".into();
    app.form.discovery = false;
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('y'));
    assert!(app.scan.as_ref().unwrap().is_running());
    use_dir(
        &mut app,
        &dir,
        Updater {
            fetch: fetch_never,
            install: install_never,
        },
    );
    press(&mut app, KeyCode::Char('S'));
    assert!(render(&mut app, 80, 24).contains("stop the running scan first"));
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.settings.job, Job::Idle), "nothing fetched");
    assert!(message(&app).starts_with("stop the running scan first"));
    app.scan.as_mut().unwrap().scan.stop();
}

#[test]
fn closing_cancels_a_check_but_a_download_finishes() {
    let dir = TempDir::new("close");
    let (_rt, mut app) = app();
    use_dir(
        &mut app,
        &dir,
        Updater {
            fetch: fetch_new,
            install: install_ok,
        },
    );
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Esc);
    assert!(!app.settings.is_open() && matches!(app.settings.job, Job::Idle));
    app.drain_events(); // a late answer goes nowhere

    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::Enter);
    settle(&mut app);
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Esc);
    assert!(!app.settings.is_open());
    settle(&mut app);
    assert!(
        app.settings
            .notice
            .as_ref()
            .unwrap()
            .0
            .starts_with("CVE data updated")
    );
    // Shown on the setup form too.
    assert!(render(&mut app, 80, 24).contains("CVE data updated"));
}

#[test]
fn url_field_validates_saves_and_resets() {
    let dir = TempDir::new("url");
    let (_rt, mut app) = app();
    use_dir(&mut app, &dir, Updater::default());
    let file = dir.0.join("settings.json");
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.settings.screen.as_ref().unwrap().focus, Row::Url);

    ctrl(&mut app, 'u');
    type_text(&mut app, "http://example.com/vulns.json");
    press(&mut app, KeyCode::Enter);
    assert!(
        message(&app).contains("Update URL not saved"),
        "{}",
        message(&app)
    );
    press(&mut app, KeyCode::Tab);
    assert_eq!(
        app.settings.screen.as_ref().unwrap().focus,
        Row::Url,
        "an invalid value keeps the focus"
    );
    assert_eq!(
        app.settings.settings.vuln_update_url,
        rmap_vuln::DEFAULT_MANIFEST_URL
    );
    assert!(!file.exists());

    ctrl(&mut app, 'u');
    type_text(&mut app, "https://mirror.example.org/vulns.json");
    press(&mut app, KeyCode::Tab); // leaving the field saves it
    assert_eq!(message(&app), "saved");
    let (saved, _) = settings::load(Some(&file));
    assert_eq!(
        saved.vuln_update_url,
        "https://mirror.example.org/vulns.json"
    );

    // Pasted escapes are dropped; a huge paste is capped.
    press(&mut app, KeyCode::BackTab);
    ctrl(&mut app, 'u');
    app.on_paste("https://a.example/\u{1b}[2J\u{7}x\nsecond line");
    let url = app.settings.screen.as_ref().unwrap().url.to_string();
    assert!(!url.chars().any(char::is_control), "{url:?}");
    assert!(!url.contains("second"));
    ctrl(&mut app, 'u');
    app.on_paste(&format!("https://{}", "a".repeat(1_000_000)));
    type_text(&mut app, "zzz");
    let input = &app.settings.screen.as_ref().unwrap().url;
    assert_eq!(input.len_chars(), MAX_URL_CHARS);
    render(&mut app, 80, 24);

    // Esc with a bad edit discards it and says so.
    ctrl(&mut app, 'u');
    type_text(&mut app, "nonsense");
    press(&mut app, KeyCode::Esc);
    assert!(
        app.settings
            .notice
            .as_ref()
            .unwrap()
            .0
            .contains("change discarded")
    );
    assert_eq!(
        settings::load(Some(&file)).0.vuln_update_url,
        "https://mirror.example.org/vulns.json"
    );

    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        settings::load(Some(&file)).0.vuln_update_url,
        rmap_vuln::DEFAULT_MANIFEST_URL
    );
}

#[test]
fn days_field_takes_1_to_365() {
    let dir = TempDir::new("days");
    let (_rt, mut app) = app();
    use_dir(&mut app, &dir, Updater::default());
    let file = dir.0.join("settings.json");
    press(&mut app, KeyCode::F(2));
    for _ in 0..4 {
        press(&mut app, KeyCode::Tab);
    }
    assert_eq!(app.settings.screen.as_ref().unwrap().focus, Row::Days);
    let days = |app: &App| app.settings.screen.as_ref().unwrap().days.to_string();

    ctrl(&mut app, 'u');
    type_text(&mut app, "0");
    press(&mut app, KeyCode::Enter);
    assert!(message(&app).contains("1 to 365"));
    assert_eq!(app.settings.settings.vuln_stale_days, 30);

    ctrl(&mut app, 'u');
    app.on_key(KeyEvent::new(KeyCode::Char('!'), KeyModifiers::SHIFT));
    type_text(&mut app, "a-9 99999");
    assert_eq!(days(&app), "999", "digits only, three at most");
    press(&mut app, KeyCode::Enter);
    assert!(message(&app).contains("1 to 365"));

    ctrl(&mut app, 'u');
    app.on_paste(" 1\u{1b}2x3\n99");
    assert_eq!(days(&app), "123");
    press(&mut app, KeyCode::Enter);
    assert_eq!(message(&app), "saved");
    assert_eq!(settings::load(Some(&file)).0.vuln_stale_days, 123);
    assert_eq!(
        crate::settings::stale_days(),
        30,
        "applied on the next frame"
    );
    render(&mut app, 80, 24);
    assert_eq!(crate::settings::stale_days(), 123);
}

#[test]
fn toggles_save_and_mouse_clicks_them() {
    let dir = TempDir::new("toggles");
    let (_rt, mut app) = app();
    use_dir(&mut app, &dir, Updater::default());
    let file = dir.0.join("settings.json");
    press(&mut app, KeyCode::F(2));
    for _ in 0..3 {
        press(&mut app, KeyCode::Tab);
    }
    press(&mut app, KeyCode::Char(' '));
    assert!(settings::load(Some(&file)).0.vuln_check_on_startup);
    press(&mut app, KeyCode::Left);
    assert!(!settings::load(Some(&file)).0.vuln_check_on_startup);

    render(&mut app, 80, 24);
    let (_, rect) = *app
        .hits
        .settings
        .iter()
        .find(|(r, _)| *r == Row::Highlight)
        .unwrap();
    app.on_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: rect.x + 15,
        row: rect.y,
        modifiers: KeyModifiers::NONE,
    });
    assert!(!app.settings.settings.vuln_highlight_exploited);
    assert!(!settings::load(Some(&file)).0.vuln_highlight_exploited);
    assert!(render(&mut app, 80, 24).contains("[ ] mark actively exploited"));
}

#[test]
fn startup_check_only_reports_newer_data() {
    let (_rt, app0) = app();
    assert!(app0.settings.startup.is_none(), "off by default");

    let dir = TempDir::new("startup");
    let updater = Updater {
        fetch: fetch_new,
        install: install_never,
    };
    let (_rt, mut app) = app();
    app.settings = SettingsState::new(None, Some(dir.0.join("vulns.db")), updater);
    app.settings.start_startup_check();
    settle(&mut app);
    let (notice, error) = app.settings.notice.clone().unwrap();
    assert_eq!(
        notice,
        "newer CVE data is available (built 2026-11-15); press F2 / S to update"
    );
    assert!(!error);
    assert!(render(&mut app, 80, 24).contains("newer CVE data is available"));

    write_db(&dir.0.join("vulns.db"), "2026-11-20T00:00:00Z");
    app.settings = SettingsState::new(None, Some(dir.0.join("vulns.db")), updater);
    app.settings.start_startup_check();
    settle(&mut app);
    assert_eq!(app.settings.notice, None, "already up to date");

    app.settings.updater.fetch = fetch_404;
    app.settings.start_startup_check();
    settle(&mut app);
    assert_eq!(app.settings.notice, None, "offline is not a banner");
}

#[test]
fn setup_form_hints_when_there_is_no_cve_data() {
    let (_rt, mut app) = app();
    let screen = render(&mut app, 80, 24);
    assert!(
        !screen.contains("no CVE data yet"),
        "unknown location: no hint"
    );
    assert!(
        screen.contains("F2") && screen.contains("settings"),
        "{screen}"
    );
    app.settings.db = DbStatus::Missing;
    let screen = render(&mut app, 80, 24);
    assert!(
        screen.contains("[ ] no CVE data yet: F2 to download"),
        "{screen}"
    );
    for line in screen.lines() {
        assert_eq!(line.chars().count(), 80, "{line:?}");
    }
}

#[test]
fn outside_text_is_cleaned() {
    let mut m = manifest("2026-11-15\u{1b}[2J");
    m.db_url = "https://ev\u{1b}]52;c;aGk=\u{7}il.example/x".into();
    let q = question(&m, &DbStatus::Missing);
    assert!(!q.chars().any(char::is_control), "{q:?}");
    let info = DbInfo {
        schema_version: 1,
        built_at: "2026-11-01".into(),
        source: "NVD\u{1b}[31m".into(),
        cve_count: 1,
    };
    let (text, _) = status_text(&DbStatus::Ready(info), 30, 0);
    assert!(!text.chars().any(char::is_control), "{text:?}");
    let (text, _) = status_text(&DbStatus::Invalid("bad\u{1b}[2J".into()), 30, 0);
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert_eq!(clean(&"x".repeat(10_000)).len(), MAX_SHOWN);
}

#[test]
fn formatting_helpers() {
    assert_eq!(thousands(0), "0");
    assert_eq!(thousands(999), "999");
    assert_eq!(thousands(1_234), "1,234");
    assert_eq!(thousands(1_234_567), "1,234,567");
    assert_eq!(size_text(1), "1 KB");
    assert_eq!(size_text(4_200_000), "4.2 MB");
    assert_eq!(
        host_of("https://u@h.example:443/p?token=secret"),
        "h.example:443"
    );
    assert_eq!(host_of("nonsense"), "nonsense");
    assert_eq!(date10("2026"), "2026");
    assert_eq!(tail("/home/a/vulns.db", 9), "…vulns.db");
    assert_eq!(tail("short", 9), "short");
    assert_eq!(tail("abc", 0), "");
    let today = crate::vuln_status::date_days("2026-11-18").unwrap();
    let ready = |built: &str| {
        DbStatus::Ready(DbInfo {
            schema_version: 1,
            built_at: built.into(),
            source: String::new(),
            cve_count: 12_345,
        })
    };
    let (text, style) = status_text(&ready("2026-11-01T00:00:00Z"), 30, today);
    assert_eq!(text, "built 2026-11-01 (17 days ago) · 12,345 CVEs");
    assert_eq!(style, Style::new());
    let (_, style) = status_text(&ready("2026-11-01"), 10, today);
    assert_eq!(style.fg, Some(Color::Yellow), "stale per the setting");
}
