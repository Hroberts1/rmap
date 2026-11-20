//! Device groups on the Hosts tab: a device's other addresses sit under its
//! first one, marked `↳`, and the details pane says why they were linked.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use ratatui::style::Stylize;
use ratatui::text::Line;
use rmap_report::DeviceGroup;

pub(crate) type Groups = BTreeMap<IpAddr, DeviceGroup>;

/// The device's first address, if `ip` is one of its others.
pub(crate) fn primary_of(ip: IpAddr, groups: &Groups) -> Option<IpAddr> {
    let first = *groups.get(&ip)?.members.first()?;
    (first != ip).then_some(first)
}

/// `ips` (filtered and sorted) with each device's other addresses moved
/// right after its first one, when that one is shown. Otherwise the order
/// is kept, so sorting still decides where each device lands.
pub(crate) fn order(ips: Vec<IpAddr>, groups: &Groups) -> Vec<IpAddr> {
    let shown: HashSet<IpAddr> = ips.iter().copied().collect();
    let tucked = |ip: &IpAddr| primary_of(*ip, groups).is_some_and(|p| shown.contains(&p));
    let mut out = Vec::with_capacity(ips.len());
    for ip in ips.iter().filter(|ip| !tucked(ip)) {
        out.push(*ip);
        if let Some(g) = groups.get(ip).filter(|g| g.members.first() == Some(ip)) {
            out.extend(g.members[1..].iter().filter(|m| shown.contains(m)));
        }
    }
    out
}

/// Detail-pane lines: the device's other addresses, then each link's reason.
pub(crate) fn detail_lines(ip: IpAddr, groups: &Groups) -> Vec<Line<'static>> {
    let Some(g) = groups.get(&ip) else {
        return Vec::new();
    };
    let others: Vec<String> = g
        .members
        .iter()
        .filter(|m| **m != ip)
        .map(IpAddr::to_string)
        .collect();
    let mut lines = vec![Line::from(vec![
        "same device as ".dim(),
        others.join(", ").into(),
    ])];
    lines.extend(g.reasons.iter().map(|r| Line::from(format!("  {r}")).dim()));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn groups(members: &[&str]) -> Groups {
        let g = DeviceGroup {
            id: 1,
            members: members.iter().map(|m| ip(m)).collect(),
            reasons: vec![],
        };
        g.members.iter().map(|m| (*m, g.clone())).collect()
    }

    #[test]
    fn others_follow_their_first_address_only_when_it_is_shown() {
        let g = groups(&["10.0.0.2", "10.0.0.9"]);
        let ips = |v: &[&str]| v.iter().map(|s| ip(s)).collect::<Vec<_>>();
        // Sorted by open ports, .9 came first: it moves under .2.
        assert_eq!(
            order(ips(&["10.0.0.9", "10.0.0.5", "10.0.0.2"]), &g),
            ips(&["10.0.0.5", "10.0.0.2", "10.0.0.9"])
        );
        // .2 filtered out: .9 stays where it was.
        assert_eq!(
            order(ips(&["10.0.0.9", "10.0.0.5"]), &g),
            ips(&["10.0.0.9", "10.0.0.5"])
        );
        assert_eq!(primary_of(ip("10.0.0.9"), &g), Some(ip("10.0.0.2")));
        assert_eq!(primary_of(ip("10.0.0.2"), &g), None);
    }

    fn render(app: &mut crate::App, w: u16, h: u16) -> String {
        use ratatui::{Terminal, backend::TestBackend};
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(w as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect()
    }

    /// A server at .10 and .30 (same MAC) and an unrelated host at .20, each
    /// with the same Samba version and CVE.
    fn two_homed(app: &mut crate::App) {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use rmap_core::{
            HostState, PortResult, PortState, Protocol, ScanEvent, Service, VulnSeverity,
            Vulnerability,
        };
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        for (addr, mac) in [
            ("192.168.1.10", "00:11:32:aa:bb:cc"),
            ("192.168.1.20", "00:50:56:00:00:01"),
            ("192.168.1.30", "00:11:32:aa:bb:cc"),
        ] {
            let ip = ip(addr);
            view.apply(ScanEvent::Host {
                ip,
                hostname: None,
                state: HostState::Up,
                rtt: None,
            });
            view.apply(ScanEvent::Mac {
                ip,
                mac: mac.parse().unwrap(),
            });
            view.apply(ScanEvent::Port {
                ip,
                result: PortResult::new(445, Protocol::Tcp, PortState::Open, None),
            });
            view.apply(ScanEvent::Service {
                ip,
                protocol: Protocol::Tcp,
                port: 445,
                service: Service {
                    name: "smb".into(),
                    product: Some("Samba".into()),
                    version: Some("4.15".into()),
                    ..Default::default()
                },
            });
            view.apply(ScanEvent::Vulnerabilities {
                ip,
                protocol: Protocol::Tcp,
                port: 445,
                findings: vec![Vulnerability {
                    id: "CVE-2099-0001".into(),
                    summary: "made up".into(),
                    severity: VulnSeverity::High,
                    score: Some(8.0),
                    published: None,
                    kev_added: None,
                }],
            });
        }
        view.selected = Some(ip("192.168.1.30"));
    }

    #[test]
    fn hosts_tab_tucks_other_addresses_and_explains_why() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = crate::App::new(rt.handle().clone());
        two_homed(&mut app);
        for (w, h) in [(80, 24), (120, 32)] {
            let screen = render(&mut app, w, h);
            let row = |a: &str| screen.find(a).unwrap();
            assert!(screen.contains("↳ 192.168.1.30"), "{w}x{h}:\n{screen}");
            assert!(row("↳ 192.168.1.30") < row("192.168.1.20"), "{screen}");
            assert!(screen.contains("same device as 192.168.1.10"), "{screen}");
            assert!(screen.contains("same MAC"), "{screen}");
        }
        // Vulns tab: the server's CVE once, with both addresses; .20's apart.
        let view = app.scan.as_mut().unwrap();
        crate::tabs::on_key(view, ratatui::crossterm::event::KeyCode::Char('3'));
        let screen = render(&mut app, 120, 32);
        assert_eq!(screen.matches("CVE-2099-0001").count(), 2, "{screen}");
        assert!(screen.contains("+ 192.168.1.30"), "{screen}");
        assert!(screen.contains("of 2"), "{screen}");
        for (w, h) in [(1, 1), (20, 8), (40, 12)] {
            render(&mut app, w, h);
        }
    }
}
