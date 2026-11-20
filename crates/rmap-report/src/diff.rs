//! Comparing two scans.
//!
//! Hosts match by address and ports by (port, protocol), so the order of
//! hosts or ports in either report doesn't matter. A host counts as present
//! when it is up (or assumed up); a host that was down in one scan and
//! absent from the other isn't reported, since it was never seen. A new
//! address of a device already present (see [`crate::devices`]) isn't a
//! new host either.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rmap_core::{HostState, MacAddr, PortResult, PortState, Protocol, Service};

use crate::model::{HostReport, ScanReport};

/// A host that appeared or disappeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChange {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    /// Its open ports in the scan where it was present.
    pub ports: Vec<(u16, Protocol)>,
}

/// A host whose up/down state flipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    pub ip: IpAddr,
    pub old: HostState,
    pub new: HostState,
}

/// A port that opened, closed, or changed state on a host present in both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortChange {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    /// State before; `None` if the port wasn't reported (closed/filtered).
    pub old: Option<PortState>,
    /// State after; `None` if the port is no longer reported.
    pub new: Option<PortState>,
    /// Service label from whichever side has one.
    pub service: Option<String>,
}

/// A port whose identified software changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceChange {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub old: String,
    pub new: String,
}

/// A host whose hardware address changed: a different device now has
/// the address (or a spoofed one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacChange {
    pub ip: IpAddr,
    pub old: MacAddr,
    pub new: MacAddr,
}

/// A host whose name changed: usually a different device now has the
/// address, or a DNS record went stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameChange {
    pub ip: IpAddr,
    pub old: String,
    pub new: String,
}

/// Everything that differs between two scans, each list sorted by address
/// then port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanDiff {
    pub new_hosts: Vec<HostChange>,
    pub gone_hosts: Vec<HostChange>,
    pub state_changes: Vec<StateChange>,
    pub opened: Vec<PortChange>,
    pub closed: Vec<PortChange>,
    /// Same port reported in both, different state (open ↔ open|filtered).
    pub port_states: Vec<PortChange>,
    pub services: Vec<ServiceChange>,
    /// Only when both scans learned a MAC for the host.
    pub macs: Vec<MacChange>,
    /// Only when both scans have a name for the host; case is ignored.
    pub names: Vec<NameChange>,
}

impl ScanDiff {
    pub fn is_empty(&self) -> bool {
        self.new_hosts.is_empty()
            && self.gone_hosts.is_empty()
            && self.state_changes.is_empty()
            && self.opened.is_empty()
            && self.closed.is_empty()
            && self.port_states.is_empty()
            && self.services.is_empty()
            && self.macs.is_empty()
            && self.names.is_empty()
    }

    /// Total number of changes.
    pub fn len(&self) -> usize {
        self.new_hosts.len()
            + self.gone_hosts.len()
            + self.state_changes.len()
            + self.opened.len()
            + self.closed.len()
            + self.port_states.len()
            + self.services.len()
            + self.macs.len()
            + self.names.len()
    }
}

fn label(s: &Service) -> String {
    match s.version_label() {
        Some(v) => format!("{} ({v})", s.name),
        None => s.name.clone(),
    }
}

fn service_label(p: &PortResult) -> Option<String> {
    p.service.as_ref().map(label)
}

/// Services differ when both sides identified something and the name,
/// product or version differs. A side with no identification (detection
/// off, or it found nothing) isn't treated as a change.
fn service_differs(a: &Service, b: &Service) -> bool {
    (&a.name, &a.product, &a.version) != (&b.name, &b.product, &b.version)
}

fn index(r: &ScanReport) -> BTreeMap<IpAddr, &HostReport> {
    // Later duplicates win, as they would in the builder.
    r.hosts.iter().map(|h| (h.ip, h)).collect()
}

fn ports(h: &HostReport) -> BTreeMap<(u16, Protocol), &PortResult> {
    h.ports.iter().map(|p| ((p.port, p.protocol), p)).collect()
}

fn host_change(h: &HostReport) -> HostChange {
    let mut ports: Vec<_> = h.ports.iter().map(|p| (p.port, p.protocol)).collect();
    ports.sort_unstable();
    ports.dedup();
    HostChange {
        ip: h.ip,
        hostname: h.hostname.clone(),
        ports,
    }
}

/// What changed from `old` to `new`.
pub fn diff(old: &ScanReport, new: &ScanReport) -> ScanDiff {
    let old_hosts = index(old);
    let new_hosts = index(new);
    let mut d = ScanDiff::default();
    let groups = crate::devices::device_groups(&new.hosts);
    // Another address of a device that was already up isn't a new host.
    let known_device = |ip: &IpAddr| {
        groups.get(ip).is_some_and(|g| {
            g.members
                .iter()
                .any(|m| old_hosts.get(m).is_some_and(|o| o.is_up()))
        })
    };

    for (ip, n) in &new_hosts {
        match old_hosts.get(ip) {
            None if n.is_up() && !known_device(ip) => d.new_hosts.push(host_change(n)),
            None => {}
            Some(o) if o.is_up() != n.is_up() => d.state_changes.push(StateChange {
                ip: *ip,
                old: o.state,
                new: n.state,
            }),
            Some(o) if o.is_up() => {
                if let (Some(old), Some(new)) = (o.mac, n.mac)
                    && old != new
                {
                    d.macs.push(MacChange { ip: *ip, old, new });
                }
                if let (Some(old), Some(new)) = (&o.hostname, &n.hostname)
                    && !old.eq_ignore_ascii_case(new)
                {
                    d.names.push(NameChange {
                        ip: *ip,
                        old: old.clone(),
                        new: new.clone(),
                    });
                }
                compare_ports(*ip, o, n, &mut d)
            }
            Some(_) => {}
        }
    }
    for (ip, o) in &old_hosts {
        if o.is_up() && !new_hosts.contains_key(ip) {
            d.gone_hosts.push(host_change(o));
        }
    }
    d
}

fn compare_ports(ip: IpAddr, old: &HostReport, new: &HostReport, d: &mut ScanDiff) {
    let before = ports(old);
    let after = ports(new);
    for (&(port, protocol), n) in &after {
        match before.get(&(port, protocol)) {
            None => d.opened.push(PortChange {
                ip,
                port,
                protocol,
                old: None,
                new: Some(n.state),
                service: service_label(n),
            }),
            Some(o) => {
                if o.state != n.state {
                    d.port_states.push(PortChange {
                        ip,
                        port,
                        protocol,
                        old: Some(o.state),
                        new: Some(n.state),
                        service: service_label(n).or_else(|| service_label(o)),
                    });
                }
                if let (Some(a), Some(b)) = (&o.service, &n.service)
                    && service_differs(a, b)
                {
                    d.services.push(ServiceChange {
                        ip,
                        port,
                        protocol,
                        old: label(a),
                        new: label(b),
                    });
                }
            }
        }
    }
    for (&(port, protocol), o) in &before {
        if !after.contains_key(&(port, protocol)) {
            d.closed.push(PortChange {
                ip,
                port,
                protocol,
                old: Some(o.state),
                new: None,
                service: service_label(o),
            });
        }
    }
}

/// How a line of the diff should be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Heading,
    Added,
    Removed,
    Changed,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}

fn line(kind: DiffKind, text: impl Into<String>) -> DiffLine {
    DiffLine {
        kind,
        text: text.into(),
    }
}

fn port_list(ports: &[(u16, Protocol)]) -> String {
    if ports.is_empty() {
        return "no open ports".into();
    }
    let shown: Vec<String> = ports
        .iter()
        .take(8)
        .map(|(p, proto)| format!("{p}/{}", proto.as_str()))
        .collect();
    let more = ports.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} +{more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

fn state_word(s: HostState) -> &'static str {
    match s {
        HostState::Up => "up",
        HostState::Assumed => "assumed up",
        HostState::Down => "down",
    }
}

fn with_name(ip: IpAddr, name: &Option<String>) -> String {
    match name {
        Some(n) => format!("{ip} ({n})"),
        None => ip.to_string(),
    }
}

fn port_line(c: &PortChange) -> String {
    let mut s = format!("{} {}/{}", c.ip, c.port, c.protocol.as_str());
    match (c.old, c.new) {
        (Some(a), Some(b)) => s.push_str(&format!("  {} → {}", a.as_str(), b.as_str())),
        (None, Some(b)) | (Some(b), None) => s.push_str(&format!("  {}", b.as_str())),
        (None, None) => {}
    }
    if let Some(svc) = &c.service {
        s.push_str(&format!("  {svc}"));
    }
    s
}

impl ScanDiff {
    /// The diff as display lines, grouped into sections. Empty sections are
    /// left out; an empty diff gives a single note.
    pub fn lines(&self) -> Vec<DiffLine> {
        let mut out = Vec::new();
        if self.is_empty() {
            out.push(line(DiffKind::Note, "No differences."));
            return out;
        }
        let mut section = |title: &str, n: usize, body: Vec<DiffLine>| {
            if n > 0 {
                if !out.is_empty() {
                    out.push(line(DiffKind::Note, ""));
                }
                out.push(line(DiffKind::Heading, format!("{title} ({n})")));
                out.extend(body);
            }
        };
        section(
            "New hosts",
            self.new_hosts.len(),
            self.new_hosts
                .iter()
                .map(|h| {
                    line(
                        DiffKind::Added,
                        format!(
                            "+ {}  {}",
                            with_name(h.ip, &h.hostname),
                            port_list(&h.ports)
                        ),
                    )
                })
                .collect(),
        );
        section(
            "Hosts gone",
            self.gone_hosts.len(),
            self.gone_hosts
                .iter()
                .map(|h| {
                    line(
                        DiffKind::Removed,
                        format!(
                            "- {}  had {}",
                            with_name(h.ip, &h.hostname),
                            port_list(&h.ports)
                        ),
                    )
                })
                .collect(),
        );
        section(
            "Host state changed",
            self.state_changes.len(),
            self.state_changes
                .iter()
                .map(|c| {
                    let kind = if c.new == HostState::Down {
                        DiffKind::Removed
                    } else {
                        DiffKind::Added
                    };
                    line(
                        kind,
                        format!("~ {}  {} → {}", c.ip, state_word(c.old), state_word(c.new)),
                    )
                })
                .collect(),
        );
        section(
            "Newly open ports",
            self.opened.len(),
            self.opened
                .iter()
                .map(|c| line(DiffKind::Added, format!("+ {}", port_line(c))))
                .collect(),
        );
        section(
            "Closed or vanished ports",
            self.closed.len(),
            self.closed
                .iter()
                .map(|c| line(DiffKind::Removed, format!("- {}", port_line(c))))
                .collect(),
        );
        section(
            "Port state changed",
            self.port_states.len(),
            self.port_states
                .iter()
                .map(|c| line(DiffKind::Changed, format!("~ {}", port_line(c))))
                .collect(),
        );
        section(
            "Service changed",
            self.services.len(),
            self.services
                .iter()
                .map(|c| {
                    line(
                        DiffKind::Changed,
                        format!(
                            "~ {} {}/{}  {} → {}",
                            c.ip,
                            c.port,
                            c.protocol.as_str(),
                            c.old,
                            c.new
                        ),
                    )
                })
                .collect(),
        );
        section(
            "Hardware changed",
            self.macs.len(),
            self.macs
                .iter()
                .map(|c| {
                    line(
                        DiffKind::Changed,
                        format!(
                            "~ {}  MAC {} → {}",
                            c.ip,
                            mac_label(c.old),
                            mac_label(c.new)
                        ),
                    )
                })
                .collect(),
        );
        section(
            "Name changed",
            self.names.len(),
            self.names
                .iter()
                .map(|c| {
                    line(
                        DiffKind::Changed,
                        format!("~ {}  {} → {}", c.ip, c.old, c.new),
                    )
                })
                .collect(),
        );
        out
    }
}

fn mac_label(mac: MacAddr) -> String {
    match rmap_oui::lookup(mac).label() {
        Some(v) => format!("{mac} ({v})"),
        None => mac.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use rmap_core::PortState::{Open, OpenFiltered};

    use super::*;
    use crate::builder::tests::{config, ip};

    fn svc(name: &str, product: Option<&str>, version: Option<&str>) -> Service {
        Service {
            name: name.into(),
            product: product.map(Into::into),
            version: version.map(Into::into),
            ..Default::default()
        }
    }

    fn host(addr: &str, state: HostState, ports: &[(u16, Protocol, PortState)]) -> HostReport {
        let mut h = HostReport::new(ip(addr), None, state);
        h.ports = ports
            .iter()
            .map(|&(p, proto, s)| PortResult::new(p, proto, s, None))
            .collect();
        h
    }

    fn report(hosts: Vec<HostReport>) -> ScanReport {
        let mut r = ScanReport::new(config(), 0);
        r.hosts = hosts;
        r
    }

    const TCP: Protocol = Protocol::Tcp;
    const UDP: Protocol = Protocol::Udp;
    const UP: HostState = HostState::Up;
    const DOWN: HostState = HostState::Down;

    #[test]
    fn empty_reports() {
        let e = report(vec![]);
        let d = diff(&e, &e);
        assert!(d.is_empty());
        assert_eq!(d.len(), 0);
        assert_eq!(d.lines(), [line(DiffKind::Note, "No differences.")]);

        let full = report(vec![host("10.0.0.1", UP, &[(22, TCP, Open)])]);
        let d = diff(&e, &full);
        assert_eq!(d.new_hosts.len(), 1);
        assert_eq!(d.new_hosts[0].ports, [(22, TCP)]);
        assert!(
            d.opened.is_empty(),
            "new hosts' ports aren't double-counted"
        );
        let d = diff(&full, &e);
        assert_eq!(d.gone_hosts.len(), 1);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn second_address_of_a_known_device_is_not_a_new_host() {
        let mac = Some("00:11:32:aa:bb:cc".parse::<MacAddr>().unwrap());
        let mut a = host("10.0.0.20", UP, &[]);
        a.mac = mac;
        let mut b = host("10.0.0.88", UP, &[]);
        b.mac = mac;
        let d = diff(&report(vec![a.clone()]), &report(vec![a, b.clone()]));
        assert!(d.new_hosts.is_empty(), "{d:?}");
        // Without the first address it's still new.
        let d = diff(&report(vec![]), &report(vec![b]));
        assert_eq!(d.new_hosts.len(), 1);
    }

    #[test]
    fn mac_changes_only_when_both_sides_know() {
        let mac = |s: &str| Some(s.parse::<MacAddr>().unwrap());
        let mut a = host("10.0.0.1", UP, &[]);
        let mut b = host("10.0.0.1", UP, &[]);
        a.mac = mac("00:11:32:00:00:01");
        let d = diff(&report(vec![a.clone()]), &report(vec![b.clone()]));
        assert!(d.is_empty(), "one side without a MAC is not a change");
        b.mac = mac("b8:27:eb:00:00:02");
        let d = diff(&report(vec![a.clone()]), &report(vec![b.clone()]));
        assert_eq!(d.len(), 1);
        assert_eq!(d.macs[0].new, b.mac.unwrap());
        assert_eq!(
            d.lines().last().unwrap().text,
            "~ 10.0.0.1  MAC 00:11:32:00:00:01 (Synology) → b8:27:eb:00:00:02 (Raspberry Pi)"
        );
        b.mac = a.mac;
        assert!(diff(&report(vec![a]), &report(vec![b])).is_empty());
    }

    #[test]
    fn name_changes_only_when_both_sides_have_one() {
        let mut a = host("10.0.0.1", UP, &[]);
        let mut b = host("10.0.0.1", UP, &[]);
        a.hostname = Some("FRONTDESK".into());
        let d = diff(&report(vec![a.clone()]), &report(vec![b.clone()]));
        assert!(d.is_empty(), "one side without a name is not a change");
        b.hostname = Some("frontdesk".into());
        let d = diff(&report(vec![a.clone()]), &report(vec![b.clone()]));
        assert!(d.is_empty(), "case is ignored");
        b.hostname = Some("LAPTOP-12".into());
        let d = diff(&report(vec![a.clone()]), &report(vec![b.clone()]));
        assert_eq!(d.len(), 1);
        assert_eq!(
            d.lines().last().unwrap().text,
            "~ 10.0.0.1  FRONTDESK → LAPTOP-12"
        );
    }

    #[test]
    fn identical_reports() {
        let mut h = host("10.0.0.1", UP, &[(22, TCP, Open), (53, UDP, OpenFiltered)]);
        h.ports[0].service = Some(svc("ssh", Some("OpenSSH"), Some("9.6")));
        let r = report(vec![h, host("10.0.0.2", DOWN, &[])]);
        assert!(diff(&r, &r).is_empty());
    }

    #[test]
    fn reordered_input_is_not_a_change() {
        let a = report(vec![
            host("10.0.0.2", UP, &[(80, TCP, Open), (22, TCP, Open)]),
            host("10.0.0.1", UP, &[(53, UDP, Open), (53, TCP, Open)]),
        ]);
        let b = report(vec![
            host("10.0.0.1", UP, &[(53, TCP, Open), (53, UDP, Open)]),
            host("10.0.0.2", UP, &[(22, TCP, Open), (80, TCP, Open)]),
        ]);
        assert!(diff(&a, &b).is_empty());
        assert!(diff(&b, &a).is_empty());
    }

    #[test]
    fn host_level_changes() {
        let old = report(vec![
            host("10.0.0.1", UP, &[(22, TCP, Open)]),
            host("10.0.0.2", UP, &[]),
            host("10.0.0.3", DOWN, &[]),
            host("10.0.0.4", DOWN, &[]),
            host("10.0.0.5", HostState::Assumed, &[]),
        ]);
        let new = report(vec![
            host("10.0.0.2", DOWN, &[]),
            host("10.0.0.3", UP, &[(80, TCP, Open)]),
            host("10.0.0.5", UP, &[]),
            host("10.0.0.6", DOWN, &[]),
            host("10.0.0.7", UP, &[]),
        ]);
        let d = diff(&old, &new);
        let ips = |v: &[HostChange]| v.iter().map(|h| h.ip.to_string()).collect::<Vec<_>>();
        assert_eq!(
            ips(&d.new_hosts),
            ["10.0.0.7"],
            "down-only hosts aren't new"
        );
        assert_eq!(ips(&d.gone_hosts), ["10.0.0.1"], "down hosts can't go");
        assert_eq!(
            d.state_changes,
            [
                StateChange {
                    ip: ip("10.0.0.2"),
                    old: UP,
                    new: DOWN
                },
                StateChange {
                    ip: ip("10.0.0.3"),
                    old: DOWN,
                    new: UP
                },
            ]
        );
        assert!(
            d.opened.is_empty(),
            "assumed → up is not a change, and no port diff across a state flip"
        );
        let text: Vec<String> = d.lines().into_iter().map(|l| l.text).collect();
        assert!(
            text.contains(&"~ 10.0.0.2  up → down".to_string()),
            "{text:?}"
        );
        assert!(
            text.contains(&"- 10.0.0.1  had 22/tcp".to_string()),
            "{text:?}"
        );
        assert!(
            text.contains(&"+ 10.0.0.7  no open ports".to_string()),
            "{text:?}"
        );
    }

    #[test]
    fn port_level_changes() {
        let mut old_h = host(
            "10.0.0.1",
            UP,
            &[
                (22, TCP, Open),
                (25, TCP, Open),
                (53, UDP, OpenFiltered),
                (80, TCP, Open),
            ],
        );
        old_h.ports[0].service = Some(svc("ssh", Some("OpenSSH"), Some("8.9")));
        old_h.ports[1].service = Some(svc("smtp", Some("Postfix"), None));
        old_h.ports[3].service = Some(svc("http", Some("nginx"), Some("1.24")));
        let mut new_h = host(
            "10.0.0.1",
            UP,
            &[
                (22, TCP, Open),
                (53, UDP, Open),
                (80, TCP, Open),
                (443, TCP, Open),
                (53, TCP, Open),
            ],
        );
        new_h.ports[0].service = Some(svc("ssh", Some("OpenSSH"), Some("9.6")));
        // 80: detection found nothing this time; not a change.
        new_h.ports[3].service = Some(svc("https", Some("nginx"), Some("1.24")));

        let d = diff(&report(vec![old_h]), &report(vec![new_h]));
        let keys = |v: &[PortChange]| v.iter().map(|c| (c.port, c.protocol)).collect::<Vec<_>>();
        assert_eq!(
            keys(&d.opened),
            [(53, TCP), (443, TCP)],
            "sorted, protocol-aware"
        );
        assert_eq!(keys(&d.closed), [(25, TCP)]);
        assert_eq!(d.closed[0].service.as_deref(), Some("smtp (Postfix)"));
        assert_eq!(keys(&d.port_states), [(53, UDP)]);
        assert_eq!(d.port_states[0].old, Some(OpenFiltered));
        assert_eq!(d.port_states[0].new, Some(Open));
        assert_eq!(
            d.services,
            [ServiceChange {
                ip: ip("10.0.0.1"),
                port: 22,
                protocol: TCP,
                old: "ssh (OpenSSH 8.9)".into(),
                new: "ssh (OpenSSH 9.6)".into(),
            }]
        );
        assert_eq!(d.len(), 5);

        let lines = d.lines();
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            text,
            [
                "Newly open ports (2)",
                "+ 10.0.0.1 53/tcp  open",
                "+ 10.0.0.1 443/tcp  open  https (nginx 1.24)",
                "",
                "Closed or vanished ports (1)",
                "- 10.0.0.1 25/tcp  open  smtp (Postfix)",
                "",
                "Port state changed (1)",
                "~ 10.0.0.1 53/udp  open|filtered → open",
                "",
                "Service changed (1)",
                "~ 10.0.0.1 22/tcp  ssh (OpenSSH 8.9) → ssh (OpenSSH 9.6)",
            ]
        );
        assert_eq!(lines[0].kind, DiffKind::Heading);
        assert_eq!(lines[1].kind, DiffKind::Added);
        assert_eq!(lines[5].kind, DiffKind::Removed);
        assert_eq!(lines[11].kind, DiffKind::Changed);
    }

    #[test]
    fn service_name_only_change_counts() {
        let mut a = host("10.0.0.1", UP, &[(8080, TCP, Open)]);
        let mut b = a.clone();
        a.ports[0].service = Some(svc("http", None, None));
        b.ports[0].service = Some(svc("http-proxy", None, None));
        let d = diff(&report(vec![a]), &report(vec![b]));
        assert_eq!(d.services[0].old, "http");
        assert_eq!(d.services[0].new, "http-proxy");
    }

    #[test]
    fn long_port_lists_are_truncated() {
        let ports: Vec<(u16, Protocol, PortState)> = (1..=20).map(|p| (p, TCP, Open)).collect();
        let d = diff(&report(vec![]), &report(vec![host("10.0.0.1", UP, &ports)]));
        let text = &d.lines()[1].text;
        assert!(text.ends_with("+12 more"), "{text}");
    }

    #[test]
    fn diff_is_symmetric_in_counts() {
        // Pseudo-random reports: the forward and backward diffs must agree.
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let mut make = || {
                let hosts = (0..(next() % 6))
                    .map(|_| {
                        let state = [UP, DOWN, HostState::Assumed][(next() % 3) as usize];
                        let ports: Vec<_> = (0..(next() % 5))
                            .map(|_| {
                                let proto = if next() % 2 == 0 { TCP } else { UDP };
                                let st = if next() % 3 == 0 { OpenFiltered } else { Open };
                                ((next() % 8) as u16 + 1, proto, st)
                            })
                            .collect();
                        host(&format!("10.0.0.{}", next() % 6), state, &ports)
                    })
                    .collect();
                report(hosts)
            };
            let (a, b) = (make(), make());
            let ab = diff(&a, &b);
            let ba = diff(&b, &a);
            assert_eq!(ab.new_hosts.len(), ba.gone_hosts.len());
            assert_eq!(ab.opened.len(), ba.closed.len());
            assert_eq!(ab.state_changes.len(), ba.state_changes.len());
            assert_eq!(ab.port_states.len(), ba.port_states.len());
            assert!(diff(&a, &a).is_empty(), "{a:?}");
            let _ = ab.lines();
        }
    }
}
