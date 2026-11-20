//! Host list filter (`/`) and sort order (`o`) on the results screen.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

use rmap_core::{VulnSeverity, service_name};

use crate::app::HostRow;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    #[default]
    Ip,
    /// Most open ports first.
    OpenPorts,
    /// Worst potential CVE first: severity, then score.
    WorstCve,
}

impl SortOrder {
    pub fn next(self) -> SortOrder {
        match self {
            SortOrder::Ip => SortOrder::OpenPorts,
            SortOrder::OpenPorts => SortOrder::WorstCve,
            SortOrder::WorstCve => SortOrder::Ip,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortOrder::Ip => "ip",
            SortOrder::OpenPorts => "ports",
            SortOrder::WorstCve => "cves",
        }
    }
}

/// Does the host match the filter text? Case-insensitive substring of the
/// address, hostname, an open port's service name or product, or an exact
/// open port number. Empty text matches everything.
pub fn matches(ip: IpAddr, host: &HostRow, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    let port: Option<u16> = q.parse().ok();
    ip.to_string().contains(&q)
        || host
            .hostname
            .as_deref()
            .is_some_and(|n| n.to_lowercase().contains(&q))
        || host.open.iter().any(|p| {
            // The name the port pane shows: detected, else the well-known one.
            let name = match &p.service {
                Some(s) => s.name.as_str(),
                None => service_name(p.port).unwrap_or(""),
            };
            port == Some(p.port)
                || name.to_lowercase().contains(&q)
                || (q == "unchecked"
                    && p.vuln_check
                        .as_ref()
                        .is_some_and(rmap_core::VulnCheck::is_unchecked))
                || p.service
                    .as_ref()
                    .and_then(|s| s.product.as_deref())
                    .is_some_and(|prod| prod.to_lowercase().contains(&q))
        })
}

/// The host's worst potential CVE as (severity, score).
fn worst_cve(host: &HostRow) -> Option<(VulnSeverity, f32)> {
    host.open
        .iter()
        .flat_map(|p| p.counted_vulns())
        .map(|v| (v.severity, v.score.unwrap_or(0.0)))
        .max_by(cmp_cve)
}

fn cmp_cve(a: &(VulnSeverity, f32), b: &(VulnSeverity, f32)) -> Ordering {
    a.0.cmp(&b.0).then(a.1.total_cmp(&b.1))
}

/// Sort `ips` (given in address order) for display. The sort is stable, so
/// ties keep address order.
pub fn sort(ips: &mut [IpAddr], hosts: &BTreeMap<IpAddr, HostRow>, order: SortOrder) {
    match order {
        SortOrder::Ip => {}
        SortOrder::OpenPorts => ips.sort_by_key(|ip| std::cmp::Reverse(hosts[ip].open.len())),
        SortOrder::WorstCve => {
            ips.sort_by(|a, b| match (worst_cve(&hosts[a]), worst_cve(&hosts[b])) {
                (Some(x), Some(y)) => cmp_cve(&y, &x),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmap_core::{HostState, PortResult, PortState, Protocol, Service, Vulnerability};

    fn host(name: Option<&str>, ports: &[u16]) -> HostRow {
        HostRow {
            hostname: name.map(Into::into),
            state: HostState::Up,
            rtt: None,
            mac: None,
            names: Vec::new(),
            open: ports
                .iter()
                .map(|&p| PortResult::new(p, Protocol::Tcp, PortState::Open, None))
                .collect(),
            closed: 0,
            filtered: 0,
            done: true,
        }
    }

    fn cve(severity: VulnSeverity, score: Option<f32>) -> Vulnerability {
        Vulnerability {
            id: "CVE-0000-0000".into(),
            summary: String::new(),
            severity,
            score,
            published: None,
            kev_added: None,
            condition: None,
            client_only: false,
        }
    }

    #[test]
    fn matches_address_name_port_and_service() {
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        let mut h = host(Some("NAS01.lan"), &[22, 445]);
        h.open[0].service = Some(Service {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            ..Default::default()
        });
        for q in [
            "", "  ", "192.168", "1.20", "nas01", "LAN", "445", "22", "SMB", "openssh", " ssh ",
        ] {
            assert!(matches(ip, &h, q), "{q:?} should match");
        }
        for q in ["10.0", "4450", "rdp", "nas02", "99999", "-1", "é"] {
            assert!(!matches(ip, &h, q), "{q:?} should not match");
        }
        assert!(!matches(ip, &host(None, &[]), "nas"), "no hostname");
    }

    #[test]
    fn sorts_by_ports_and_worst_cve_with_address_ties() {
        let ips: Vec<IpAddr> = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let mut hosts = BTreeMap::new();
        hosts.insert(ips[0], host(None, &[22]));
        hosts.insert(ips[1], host(None, &[22, 80, 443]));
        hosts.insert(ips[2], host(None, &[22]));
        hosts.insert(ips[3], host(None, &[22, 80]));
        hosts.get_mut(&ips[0]).unwrap().open[0].vulnerabilities =
            vec![cve(VulnSeverity::Medium, Some(9.0))];
        hosts.get_mut(&ips[2]).unwrap().open[0].vulnerabilities = vec![
            cve(VulnSeverity::Low, Some(3.0)),
            cve(VulnSeverity::High, Some(7.5)),
        ];
        hosts.get_mut(&ips[3]).unwrap().open[1].vulnerabilities =
            vec![cve(VulnSeverity::High, None)];

        let sorted = |order| {
            let mut v = ips.clone();
            sort(&mut v, &hosts, order);
            v.iter().map(|ip| ip.to_string()).collect::<Vec<_>>()
        };
        assert_eq!(
            sorted(SortOrder::Ip),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        );
        assert_eq!(
            sorted(SortOrder::OpenPorts),
            ["10.0.0.2", "10.0.0.4", "10.0.0.1", "10.0.0.3"]
        );
        // High 7.5, High (no score), Medium 9.0, then the host without CVEs.
        assert_eq!(
            sorted(SortOrder::WorstCve),
            ["10.0.0.3", "10.0.0.4", "10.0.0.1", "10.0.0.2"]
        );
    }

    #[test]
    fn sort_order_cycles() {
        let mut o = SortOrder::default();
        let labels: Vec<_> = (0..4)
            .map(|_| {
                let l = o.label();
                o = o.next();
                l
            })
            .collect();
        assert_eq!(labels, ["ip", "ports", "cves", "ip"]);
    }
}
