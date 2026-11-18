//! Parsing for the setup form's safety fields: addresses to exclude and the
//! probe-rate cap, for networks with fragile devices.

use rmap_core::{Target, parse_targets};

/// The Exclude field: target syntax, or empty for no exclusions.
pub fn parse_exclude(input: &str) -> Result<Vec<Target>, String> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    parse_targets(input).map_err(|e| e.to_string())
}

/// The Max rate field: probes per second, or empty for unlimited.
pub fn parse_max_rate(input: &str) -> Result<Option<u32>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "{s}: use a whole number of probes per second (e.g. 50), or leave empty for unlimited"
        ));
    }
    match s.parse::<u32>() {
        Ok(0) => Err("must be at least 1 probe per second; leave empty for unlimited".into()),
        Ok(n) => Ok(Some(n)),
        Err(_) => Err(format!("{s}: too large; leave empty for unlimited")),
    }
}

/// The DNS server field: an IP address, or empty for the system's resolver.
pub fn parse_dns_server(input: &str) -> Result<Option<std::net::IpAddr>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse()
        .map(Some)
        .map_err(|_| format!("{s}: use an IP address such as 10.0.0.10, or leave empty"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_server_is_an_address_or_empty() {
        assert_eq!(parse_dns_server("  "), Ok(None));
        assert_eq!(
            parse_dns_server(" 10.0.0.10 "),
            Ok(Some("10.0.0.10".parse().unwrap()))
        );
        assert_eq!(
            parse_dns_server("2001:db8::53"),
            Ok(Some("2001:db8::53".parse().unwrap()))
        );
        for bad in ["dc01.corp.lan", "10.0.0.10:53", "10.0.0", "\u{1b}[2J"] {
            assert!(parse_dns_server(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn max_rate_accepts_numbers_and_empty() {
        assert_eq!(parse_max_rate(""), Ok(None));
        assert_eq!(parse_max_rate("  "), Ok(None));
        assert_eq!(parse_max_rate("50"), Ok(Some(50)));
        assert_eq!(parse_max_rate(" 007 "), Ok(Some(7)));
        assert_eq!(parse_max_rate("4294967295"), Ok(Some(u32::MAX)));
    }

    #[test]
    fn max_rate_rejects_junk_without_panicking() {
        for bad in [
            "0",
            "000",
            "-5",
            "+5",
            "5.5",
            "1e3",
            "50/s",
            "4294967296",
            "99999999999999999999999",
            "٣",
            "\u{1b}[31m",
        ] {
            assert!(parse_max_rate(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn exclude_is_optional_and_uses_target_syntax() {
        assert_eq!(parse_exclude(""), Ok(Vec::new()));
        assert_eq!(parse_exclude(" ,"), Err("no targets given".into()));
        assert_eq!(parse_exclude("192.0.2.1, 192.0.2.8/30").unwrap().len(), 2);
        assert!(parse_exclude("192.0.2.300").is_err());
    }

    #[test]
    fn random_input_never_panics() {
        // Small xorshift so the test needs no extra crates and is repeatable.
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let alphabet: Vec<char> = "0123456789.,-/: abcxyz\u{1b}\u{0}é٣".chars().collect();
        for _ in 0..5_000 {
            let len = (x % 24) as usize;
            let s: String = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    alphabet[(x % alphabet.len() as u64) as usize]
                })
                .collect();
            let _ = parse_max_rate(&s);
            let _ = parse_exclude(&s);
        }
    }

    // ------------------------------------------------- setup form hooks

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use crate::app::{App, Field, Screen};

    fn app() -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let app = App::new(rt.handle().clone());
        (rt, app)
    }

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
    fn new_fields_fit_at_80x24_with_an_error_showing() {
        let (_rt, mut app) = app();
        app.form.targets = "192.0.2.0/24".into();
        app.form.max_rate = "fast".into();
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.form.focus, Field::MaxRate);
        for (w, h) in [(80, 24), (120, 40)] {
            let screen = render(&mut app, w, h);
            for want in [
                "Targets",
                "Exclude",
                "never probe these",
                "Ports",
                "Timing",
                "Max rate",
                "Vulns",
                "Max rate: fast: use a whole number",
                "logging off",
            ] {
                assert!(screen.contains(want), "{w}x{h} missing {want:?}\n{screen}");
            }
        }
        // Tiny terminals must not panic.
        render(&mut app, 20, 6);
        render(&mut app, 1, 1);
    }

    #[test]
    fn tab_order_visits_the_new_fields() {
        let (_rt, mut app) = app();
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.form.focus, Field::Exclude);
        for c in "192.0.2.9,".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.form.exclude, "192.0.2.9,");
        for _ in 0..4 {
            press(&mut app, KeyCode::Tab);
        }
        assert_eq!(app.form.focus, Field::MaxRate);
        app.on_paste("25\nignored");
        assert_eq!(app.form.max_rate, "25");
        app.form.focus = Field::Exclude;
        app.on_paste("\r\n192.0.2.10\n192.0.2.11\n");
        assert_eq!(app.form.exclude, "192.0.2.9,192.0.2.10,192.0.2.11");
    }

    #[test]
    fn name_fields_toggle_validate_and_reach_the_config() {
        let (_rt, mut app) = app();
        app.form.resolve_names = true;
        app.form.focus = Field::Names;
        press(&mut app, KeyCode::Char(' '));
        assert!(!app.form.resolve_names);
        press(&mut app, KeyCode::Char(' '));
        assert!(app.form.resolve_names);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.form.focus, Field::DnsServer);
        app.on_paste("dc01.corp.lan\nignored");
        app.form.targets = "192.168.50.0/30".into();
        press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Setup));
        assert_eq!(app.form.focus, Field::DnsServer);
        let screen = render(&mut app, 80, 24);
        for want in [
            "Names",
            "reverse DNS, NetBIOS, mDNS",
            "DNS server: dc01.corp.lan",
        ] {
            assert!(screen.contains(want), "missing {want:?}\n{screen}");
        }

        app.form.dns_server = " 10.0.0.10 ".into();
        app.form.discovery = false;
        // Names on with the scan stopped at once: no lookups go anywhere
        // beyond the private test range.
        app.form.resolve_names = false;
        press(&mut app, KeyCode::Enter);
        let view = app.scan.as_mut().expect("scan started");
        view.scan.stop();
        view.stopped = true;
        let config = view.report.report().config;
        assert_eq!(config.dns_server, Some("10.0.0.10".parse().unwrap()));
        assert!(!config.resolve_names);
    }

    #[test]
    fn bad_exclude_and_full_exclusion_are_rejected_inline() {
        let (_rt, mut app) = app();
        app.form.targets = "192.0.2.0/30".into();
        app.form.exclude = "192.0.2.999".into();
        press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Setup));
        assert_eq!(app.form.focus, Field::Exclude);
        assert!(render(&mut app, 80, 24).contains("Exclude: 192.0.2.999"));

        app.form.exclude = "192.0.2.0-192.0.2.1, 192.0.2.2/31".into();
        press(&mut app, KeyCode::Enter);
        assert!(app.scan.is_none());
        assert!(render(&mut app, 80, 24).contains("every target address is excluded"));
    }

    #[test]
    fn scope_and_rate_reach_the_report_and_header() {
        let (_rt, mut app) = app();
        app.form.targets = "192.0.2.0/30".into();
        app.form.exclude = " 192.0.2.1 ".into();
        app.form.max_rate = "10".into();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        // TEST-NET-1 isn't private space, so it asks first.
        press(&mut app, KeyCode::Char('y'));
        let view = app.scan.as_mut().expect("scan started");
        view.scan.stop();
        view.stopped = true;
        let config = view.report.report().config;
        assert_eq!(config.exclude, "192.0.2.1");
        assert_eq!(config.max_rate, Some(10));
        let header = render(&mut app, 120, 30);
        assert!(
            header.contains("max 10/s · excluding 192.0.2.1"),
            "{header}"
        );
    }
}
