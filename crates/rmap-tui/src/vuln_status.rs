//! Honest CVE coverage on the results screen: each port's check status,
//! how many ports couldn't be checked, and how old the CVE data is.

use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use rmap_core::{VulnCheck, VulnData};

use crate::app::ScanView;

/// CVE data older than this many days is flagged in the header; set in
/// Settings (`vuln_stale_days`).
pub(crate) fn stale_after_days() -> i64 {
    i64::from(crate::settings::stale_days())
}

/// The detail pane's status line for a port and its style, or `None` for
/// a port with matches (its CVE lines already say so).
pub(crate) fn detail(check: &VulnCheck) -> Option<(String, Style)> {
    match check {
        VulnCheck::Checked { matches: 1.., .. } => None,
        VulnCheck::Checked { .. } => Some((check.to_string(), Style::new().dim())),
        _ => Some((check.to_string(), Style::new().fg(Color::Yellow))),
    }
}

/// For the header's bottom border: ` 3 unchecked · CVE data 2026-11-01 `.
/// "unchecked" counts ports that couldn't be checked; the data's age
/// replaces its date, in a warning style, once stale. `None` when there
/// is nothing to say (matching off).
pub(crate) fn header_line(view: &ScanView) -> Option<Line<'static>> {
    let mut spans = Vec::new();
    let unchecked = view
        .hosts
        .values()
        .flat_map(|h| &h.open)
        .filter(|p| p.vuln_check.as_ref().is_some_and(VulnCheck::is_unchecked))
        .count();
    if unchecked > 0 {
        spans.push(Span::raw(format!("{unchecked} unchecked")).fg(Color::Yellow));
    }
    if let Some(data) = view.report.vuln_data() {
        let today = rmap_report::unix_millis_now().div_euclid(86_400_000);
        if !spans.is_empty() {
            spans.push(Span::raw(" · "));
        }
        spans.push(data_span(data, today));
    }
    if spans.is_empty() {
        return None;
    }
    spans.insert(0, Span::raw(" "));
    spans.push(Span::raw(" "));
    Some(Line::from(spans))
}

/// `CVE data 2026-11-01`, or `CVE data 45 days old` once stale.
fn data_span(data: &VulnData, today: i64) -> Span<'static> {
    match date_days(&data.built_at) {
        Some(built) if today - built > stale_after_days() => {
            Span::raw(format!("CVE data {} days old", today - built))
                .fg(Color::Yellow)
                .bold()
        }
        Some(_) => Span::raw(format!("CVE data {}", &data.built_at[..10])).dim(),
        None => Span::raw("CVE data date unknown").fg(Color::Yellow),
    }
}

/// Days since 1970-01-01 of a string starting `YYYY-MM-DD`.
pub(crate) fn date_days(s: &str) -> Option<i64> {
    let date = s.get(..10)?;
    let mut parts = date.split('-');
    let mut num = |len: usize| {
        let p = parts.next()?;
        (p.len() == len && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse::<i64>().ok())
            .flatten()
    };
    let (y, m, d) = (num(4)?, num(2)?, num(2)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rmap_core::{
        HostState, PortResult, PortState, Protocol, ScanEvent, Service, VulnSeverity, Vulnerability,
    };

    use super::*;
    use crate::App;

    #[test]
    fn dates_parse_to_days() {
        assert_eq!(date_days("1970-01-01"), Some(0));
        assert_eq!(date_days("2000-03-01T00:00:00Z"), Some(11_017));
        assert_eq!(date_days("2026-11-18"), Some(20_775));
        for bad in [
            "",
            "2026-11",
            "2026-13-01",
            "2026-00-10",
            "+026-11-01",
            "2026/11/01",
            "é",
        ] {
            assert_eq!(date_days(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn stale_data_is_flagged() {
        let data = |built_at: &str| VulnData {
            built_at: built_at.into(),
            cve_count: 1,
            source: "test".into(),
        };
        let today = date_days("2026-11-18").unwrap();
        assert_eq!(
            data_span(&data("2026-11-01T00:00:00Z"), today).content,
            "CVE data 2026-11-01"
        );
        assert_eq!(
            data_span(&data("2026-10-04"), today).content,
            "CVE data 45 days old"
        );
        assert_eq!(
            data_span(&data("soon"), today).content,
            "CVE data date unknown"
        );
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

    const IP: &str = "10.0.0.2";

    /// A stopped scan of one host with a port for every check status, one
    /// KEV-listed CVE, and CVE data built on `built_at`.
    fn audited(app: &mut App, built_at: &str) {
        app.store = None;
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        let ip: IpAddr = IP.parse().unwrap();
        view.apply(ScanEvent::VulnData(VulnData {
            built_at: built_at.into(),
            cve_count: 245_000,
            source: "test".into(),
        }));
        view.apply(ScanEvent::Host {
            ip,
            hostname: None,
            state: HostState::Up,
            rtt: None,
        });
        let product = |p: &str| p.to_string();
        let ports = [
            (
                22,
                VulnCheck::Checked {
                    product: product("OpenSSH"),
                    version: "9.6p1".into(),
                    matches: 1,
                },
            ),
            (
                80,
                VulnCheck::Checked {
                    product: product("nginx"),
                    version: "1.24.0".into(),
                    matches: 0,
                },
            ),
            (
                443,
                VulnCheck::VersionHidden {
                    product: product("nginx"),
                },
            ),
            (
                21,
                VulnCheck::NotCovered {
                    product: product("vsftpd"),
                },
            ),
            (23, VulnCheck::NoProduct),
            (25, VulnCheck::NoDatabase),
        ];
        for (port, status) in ports {
            view.apply(ScanEvent::Port {
                ip,
                result: PortResult::new(port, Protocol::Tcp, PortState::Open, None),
            });
            view.apply(ScanEvent::Service {
                ip,
                protocol: Protocol::Tcp,
                port,
                service: Service {
                    name: "svc".into(),
                    ..Default::default()
                },
            });
            if port == 22 {
                view.apply(ScanEvent::Vulnerabilities {
                    ip,
                    protocol: Protocol::Tcp,
                    port,
                    findings: vec![Vulnerability {
                        id: "CVE-2024-6387".into(),
                        summary: "regreSSHion".into(),
                        severity: VulnSeverity::High,
                        score: Some(8.1),
                        published: None,
                        kev_added: Some("2024-07-15".into()),
                    }],
                });
            }
            view.apply(ScanEvent::VulnCheck {
                ip,
                protocol: Protocol::Tcp,
                port,
                status,
            });
        }
        view.selected = Some(ip);
    }

    fn today() -> String {
        let t = rmap_log::Timestamp::now();
        format!("{:04}-{:02}-{:02}", t.year, t.month, t.day)
    }

    #[test]
    fn statuses_header_and_kev_render() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        audited(&mut app, &today());
        // Tall enough that every port's lines fit in the detail pane.
        for (w, h) in [(80, 40), (160, 40)] {
            let screen = render(&mut app, w, h);
            for needle in [
                "4 unchecked",
                &format!("CVE data {}", today()),
                "no known CVEs for nginx 1.24.0",
                "nginx detected, version unknown: can't check",
                "no CVE data for vsftpd: not checked",
                "product not identified: can't check",
                "no vulnerability data: not checked",
                "actively exploited",
            ] {
                assert!(screen.contains(needle), "{needle} at {w}x{h}:\n{screen}");
            }
            // The CVE line already says it; no duplicate status line.
            assert!(!screen.contains("1 potential CVE ("), "{screen}");
            if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
                println!("{screen}");
            }
        }
    }

    #[test]
    fn vulns_tab_marks_exploited() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        audited(&mut app, &today());
        app.on_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
        for (w, h) in [(80, 24), (160, 40)] {
            let screen = render(&mut app, w, h);
            assert!(
                screen.contains("actively exploited (CISA KEV"),
                "at {w}x{h}:\n{screen}"
            );
        }
    }

    #[test]
    fn stale_data_shows_in_the_header_at_80_columns() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        audited(&mut app, "2000-01-01");
        let screen = render(&mut app, 80, 24);
        assert!(screen.contains("4 unchecked · CVE data "), "{screen}");
        assert!(screen.contains(" days old"), "{screen}");
        for line in screen.lines() {
            assert_eq!(line.chars().count(), 80, "{line:?}");
        }
    }

    #[test]
    fn kev_line_follows_the_setting() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        audited(&mut app, &today());
        app.settings.settings.vuln_highlight_exploited = false;
        let screen = render(&mut app, 160, 40);
        assert!(screen.contains("CVE-2024-6387"), "{screen}");
        assert!(!screen.contains("actively exploited"), "{screen}");
        app.on_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
        let screen = render(&mut app, 160, 40);
        assert!(screen.contains("CVE-2024-6387"), "{screen}");
        assert!(!screen.contains("actively exploited (CISA KEV"), "{screen}");
    }

    #[test]
    fn stale_threshold_follows_the_setting() {
        let data = VulnData {
            built_at: "2026-10-04".into(),
            cve_count: 1,
            source: "test".into(),
        };
        let today = date_days("2026-11-18").unwrap();
        crate::settings::set_display(&crate::settings::Settings {
            vuln_stale_days: 60,
            ..Default::default()
        });
        assert_eq!(data_span(&data, today).content, "CVE data 2026-10-04");
        crate::settings::set_display(&crate::settings::Settings {
            vuln_stale_days: 7,
            ..Default::default()
        });
        assert_eq!(data_span(&data, today).content, "CVE data 45 days old");
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        audited(&mut app, "2000-01-01");
        for (w, h) in [(1, 1), (20, 6), (40, 12), (80, 24)] {
            render(&mut app, w, h);
        }
        app.on_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
        for (w, h) in [(1, 1), (20, 6), (40, 12)] {
            render(&mut app, w, h);
        }
    }
}
