//! Host names (reverse DNS, NetBIOS, mDNS) on the results screen.

use ratatui::style::Stylize;
use ratatui::text::{Line, Span};

use crate::app::HostRow;

/// `names frontdesk.corp.lan (DNS) · FRONTDESK (NetBIOS)` for the detail
/// pane, when any were found. Showing the source tells a stale DNS record
/// (DNS and NetBIOS disagree) from a device that names itself.
pub(crate) fn detail_line(h: &HostRow) -> Option<Line<'static>> {
    if h.names.is_empty() {
        return None;
    }
    let mut spans = vec![Span::raw("names ").dim()];
    for (i, n) in h.names.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" · ").dim());
        }
        spans.push(Span::raw(n.name.clone()));
        spans.push(Span::raw(format!(" ({})", n.source)).dim());
    }
    Some(Line::from(spans))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rmap_core::{HostName, HostState, NameSource, ScanEvent};

    use crate::App;

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// A results view with one host, fed synthetic events.
    fn app_with(names: Vec<HostName>, typed: Option<&str>) -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        view.apply(ScanEvent::Host {
            ip,
            hostname: typed.map(Into::into),
            state: HostState::Up,
            rtt: None,
        });
        view.apply(ScanEvent::Hostnames { ip, names });
        view.selected = Some(ip);
        (rt, app)
    }

    fn n(name: &str, source: NameSource) -> HostName {
        HostName::new(name, source).unwrap()
    }

    #[test]
    fn best_name_fills_the_table_and_all_show_in_detail() {
        let names = vec![
            n("frontdesk.corp.lan", NameSource::Dns),
            n("FRONTDESK", NameSource::Netbios),
        ];
        let (_rt, mut app) = app_with(names, None);
        let host = &app.scan.as_ref().unwrap().hosts[&"10.0.0.9".parse().unwrap()];
        assert_eq!(host.hostname.as_deref(), Some("frontdesk.corp.lan"));
        for (w, h) in [(80, 24), (140, 40)] {
            let screen = render(&mut app, w, h);
            assert!(screen.contains("frontdesk"), "table at {w}x{h}:\n{screen}");
            assert!(screen.contains("(NetBIOS)"), "detail at {w}x{h}:\n{screen}");
        }
        render(&mut app, 20, 6); // tiny terminals must not panic
    }

    #[test]
    fn a_typed_hostname_is_kept() {
        let (_rt, app) = app_with(vec![n("nas-01.local", NameSource::Mdns)], Some("nas.lan"));
        let host = &app.scan.as_ref().unwrap().hosts[&"10.0.0.9".parse().unwrap()];
        assert_eq!(host.hostname.as_deref(), Some("nas.lan"));
        assert_eq!(host.names.len(), 1);
    }
}
