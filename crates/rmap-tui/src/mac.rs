//! MAC address and hardware vendor on the results screen.

use ratatui::style::Stylize;
use ratatui::text::{Line, Span};

use crate::app::HostRow;

/// What the host table's NAME column shows: the hostname, or else the
/// hardware vendor (or "random MAC").
pub(crate) fn host_name(h: &HostRow) -> Option<&str> {
    h.hostname
        .as_deref()
        .or_else(|| h.mac.and_then(|m| rmap_oui::lookup(m).label()))
}

/// `mac 00:11:32:aa:bb:cc · Synology` for the detail pane, when known.
pub(crate) fn detail_line(h: &HostRow) -> Option<Line<'static>> {
    let mac = h.mac?;
    let mut spans = vec![Span::raw("mac ").dim(), Span::raw(mac.to_string())];
    if let Some(vendor) = rmap_oui::lookup(mac).label() {
        spans.push(Span::raw(format!(" · {vendor}")).dim());
    }
    Some(Line::from(spans))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rmap_core::{HostState, ScanEvent};

    use crate::App;

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(w.max(1) as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect()
    }

    /// A results view with a Synology NAS, a randomised-MAC laptop and a
    /// named Brother printer, fed synthetic events.
    fn lan(app: &mut App) {
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        for (ip, name, mac) in [
            ("192.168.1.20", None, "00:11:32:aa:bb:cc"),
            ("192.168.1.21", None, "da:a1:19:00:00:01"),
            ("192.168.1.22", Some("printer.lan"), "00:80:77:00:00:01"),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            view.apply(ScanEvent::Host {
                ip,
                hostname: name.map(Into::into),
                state: HostState::Up,
                rtt: None,
            });
            view.apply(ScanEvent::Mac {
                ip,
                mac: mac.parse().unwrap(),
            });
        }
        view.selected = Some("192.168.1.20".parse().unwrap());
    }

    #[test]
    fn vendor_in_table_and_mac_in_detail() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        lan(&mut app);
        for (w, h) in [(80, 24), (120, 32)] {
            let screen = render(&mut app, w, h);
            for needle in [
                "Synology",
                "random MAC",
                "printer.lan",
                "mac 00:11:32:aa:bb:cc · Synology",
            ] {
                assert!(screen.contains(needle), "{needle} at {w}x{h}:\n{screen}");
            }
            assert!(
                !screen.contains("Brother"),
                "a hostname wins over the vendor in the table at {w}x{h}:\n{screen}"
            );
            if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
                println!("{screen}");
            }
        }
        let report = app.scan.as_ref().unwrap().report.report();
        assert_eq!(report.hosts[0].vendor.as_deref(), Some("Synology"));
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        lan(&mut app);
        for (w, h) in [(1, 1), (10, 5), (20, 8), (40, 12)] {
            render(&mut app, w, h);
        }
    }
}
