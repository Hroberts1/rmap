//! Turns the engine's event stream into a [`ScanReport`].

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use rmap_core::{Protocol, ScanEvent, Service, VulnData, Vulnerability};

use crate::model::{ConfigSummary, HostReport, RunStatus, ScanReport};

/// Collects [`ScanEvent`]s into a report. Pure: the caller supplies the
/// clock, so the same events always give the same report.
#[derive(Debug, Clone)]
pub struct ReportBuilder {
    report: ScanReport,
    hosts: BTreeMap<IpAddr, HostReport>,
    /// Services that arrived before their port, attached when it shows up.
    early_services: HashMap<(IpAddr, Protocol, u16), Service>,
    /// Vulnerability findings that arrived before their port, attached
    /// when it shows up.
    early_vulnerabilities: HashMap<(IpAddr, Protocol, u16), Vec<Vulnerability>>,
    /// Events that referred to a host or port we hadn't seen.
    orphans: u64,
}

impl ReportBuilder {
    pub fn new(config: ConfigSummary, started_ms: i64) -> Self {
        ReportBuilder {
            report: ScanReport::new(config, started_ms),
            hosts: BTreeMap::new(),
            early_services: HashMap::new(),
            early_vulnerabilities: HashMap::new(),
            orphans: 0,
        }
    }

    pub fn status(&self) -> RunStatus {
        self.report.status
    }

    /// Events dropped because they referred to an unknown host.
    pub fn orphans(&self) -> u64 {
        self.orphans
    }

    pub fn apply(&mut self, event: &ScanEvent) {
        match event {
            ScanEvent::Started { .. } | ScanEvent::Warning(_) => {}
            ScanEvent::Host {
                ip,
                hostname,
                state,
                rtt,
            } => {
                let mut host = HostReport::new(*ip, hostname.clone(), *state);
                host.rtt = *rtt;
                self.hosts.insert(*ip, host);
            }
            ScanEvent::Mac { ip, mac } => match self.hosts.get_mut(ip) {
                Some(h) => {
                    h.mac = Some(*mac);
                    h.vendor = rmap_oui::lookup(*mac).name().map(Into::into);
                }
                None => self.orphans += 1,
            },
            ScanEvent::Hostnames { ip, names } => match self.hosts.get_mut(ip) {
                Some(h) => {
                    if h.hostname.is_none() {
                        h.hostname = names.first().map(|n| n.name.clone());
                    }
                    h.names = names.clone();
                }
                None => self.orphans += 1,
            },
            ScanEvent::Port { ip, result } => {
                let Some(host) = self.hosts.get_mut(ip) else {
                    self.orphans += 1;
                    return;
                };
                let mut result = result.clone();
                if let Some(service) =
                    self.early_services
                        .remove(&(*ip, result.protocol, result.port))
                {
                    result.service = Some(service);
                }
                if let Some(findings) =
                    self.early_vulnerabilities
                        .remove(&(*ip, result.protocol, result.port))
                {
                    result.vulnerabilities = findings;
                }
                let key = (result.port, result.protocol);
                match host
                    .ports
                    .binary_search_by_key(&key, |p| (p.port, p.protocol))
                {
                    Ok(i) => host.ports[i] = result,
                    Err(i) => host.ports.insert(i, result),
                }
            }
            ScanEvent::Service {
                ip,
                protocol,
                port,
                service,
            } => {
                let Some(host) = self.hosts.get_mut(ip) else {
                    self.orphans += 1;
                    return;
                };
                match host
                    .ports
                    .iter_mut()
                    .find(|p| p.port == *port && p.protocol == *protocol)
                {
                    Some(p) => p.service = Some(service.clone()),
                    None => {
                        self.early_services
                            .insert((*ip, *protocol, *port), service.clone());
                    }
                }
            }
            ScanEvent::Vulnerabilities {
                ip,
                protocol,
                port,
                findings,
            } => {
                let Some(host) = self.hosts.get_mut(ip) else {
                    self.orphans += 1;
                    return;
                };
                match host
                    .ports
                    .iter_mut()
                    .find(|p| p.port == *port && p.protocol == *protocol)
                {
                    Some(p) => p.vulnerabilities = findings.clone(),
                    None => {
                        self.early_vulnerabilities
                            .insert((*ip, *protocol, *port), findings.clone());
                    }
                }
            }
            ScanEvent::VulnCheck {
                ip,
                protocol,
                port,
                status,
            } => {
                // Sent after its Service, so the port is already here.
                match self.hosts.get_mut(ip).and_then(|h| {
                    h.ports
                        .iter_mut()
                        .find(|p| p.port == *port && p.protocol == *protocol)
                }) {
                    Some(p) => p.vuln_check = Some(status.clone()),
                    None => self.orphans += 1,
                }
            }
            ScanEvent::VulnData(data) => self.report.vuln_data = Some(data.clone()),
            ScanEvent::HostDone {
                ip,
                closed,
                filtered,
                ..
            } => match self.hosts.get_mut(ip) {
                Some(h) => {
                    h.closed = *closed;
                    h.filtered = *filtered;
                    h.complete = true;
                }
                None => self.orphans += 1,
            },
            ScanEvent::Finished { elapsed } => {
                if self.report.status == RunStatus::Running {
                    self.report.status = RunStatus::Completed;
                    self.report.finished_ms =
                        Some(self.report.started_ms + elapsed.as_millis() as i64);
                }
            }
        }
    }

    /// The user stopped the scan at `now_ms`.
    pub fn mark_stopped(&mut self, now_ms: i64) {
        self.end(RunStatus::Stopped, now_ms);
    }

    /// The engine died at `now_ms`.
    pub fn mark_failed(&mut self, now_ms: i64) {
        self.end(RunStatus::Failed, now_ms);
    }

    fn end(&mut self, status: RunStatus, now_ms: i64) {
        if self.report.status == RunStatus::Running {
            self.report.status = status;
            self.report.finished_ms = Some(now_ms.max(self.report.started_ms));
        }
    }

    /// The CVE database the scan matched against, once known.
    pub fn vuln_data(&self) -> Option<&VulnData> {
        self.report.vuln_data.as_ref()
    }

    /// The report as it stands.
    pub fn report(&self) -> ScanReport {
        let mut report = self.report.clone();
        report.hosts = self.hosts.values().cloned().collect();
        crate::tags::tag_hosts(&mut report.hosts);
        report
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use rmap_core::{HostState, PortResult, PortState, ScanType};

    use super::*;

    pub(crate) fn config() -> ConfigSummary {
        ConfigSummary {
            targets: "10.0.0.0/30".into(),
            ports: "22,80,443".into(),
            port_count: 3,
            scan_type: ScanType::Connect,
            timing_level: 3,
            timing_name: "normal".into(),
            discovery: true,
            service_detection: true,
            exclude: String::new(),
            max_rate: None,
            resolve_names: true,
            dns_server: None,
        }
    }

    pub(crate) fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn host(b: &mut ReportBuilder, addr: &str, state: HostState) {
        b.apply(&ScanEvent::Host {
            ip: ip(addr),
            hostname: None,
            state,
            rtt: Some(Duration::from_millis(2)),
        });
    }

    fn port(b: &mut ReportBuilder, addr: &str, port: u16, protocol: Protocol) {
        b.apply(&ScanEvent::Port {
            ip: ip(addr),
            result: PortResult::new(port, protocol, PortState::Open, None),
        });
    }

    fn ssh(version: &str) -> Service {
        Service {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: Some(version.into()),
            ..Default::default()
        }
    }

    #[test]
    fn builds_a_sorted_report() {
        let mut b = ReportBuilder::new(config(), 1_000);
        b.apply(&ScanEvent::Started {
            hosts: 3,
            ports_per_host: 3,
        });
        host(&mut b, "10.0.0.2", HostState::Up);
        host(&mut b, "10.0.0.1", HostState::Down);
        port(&mut b, "10.0.0.2", 443, Protocol::Tcp);
        port(&mut b, "10.0.0.2", 22, Protocol::Tcp);
        port(&mut b, "10.0.0.2", 22, Protocol::Udp);
        b.apply(&ScanEvent::Service {
            ip: ip("10.0.0.2"),
            protocol: Protocol::Tcp,
            port: 22,
            service: ssh("9.6p1"),
        });
        b.apply(&ScanEvent::HostDone {
            ip: ip("10.0.0.2"),
            closed: 1,
            filtered: 0,
            elapsed: Duration::from_millis(5),
        });
        b.apply(&ScanEvent::Warning("ignored".into()));
        assert_eq!(b.status(), RunStatus::Running);
        b.apply(&ScanEvent::Finished {
            elapsed: Duration::from_millis(2_500),
        });

        let r = b.report();
        assert_eq!(r.status, RunStatus::Completed);
        assert_eq!(r.finished_ms, Some(3_500));
        assert_eq!(r.elapsed(), Duration::from_millis(2_500));
        let addrs: Vec<String> = r.hosts.iter().map(|h| h.ip.to_string()).collect();
        assert_eq!(addrs, ["10.0.0.1", "10.0.0.2"]);
        let h = r.host(ip("10.0.0.2")).unwrap();
        let ports: Vec<(u16, Protocol)> = h.ports.iter().map(|p| (p.port, p.protocol)).collect();
        assert_eq!(
            ports,
            [
                (22, Protocol::Tcp),
                (22, Protocol::Udp),
                (443, Protocol::Tcp)
            ]
        );
        assert_eq!(h.ports[0].service, Some(ssh("9.6p1")));
        assert!(h.ports[1].service.is_none(), "udp/22 untouched");
        assert!(h.complete && h.closed == 1);
        assert!(
            r.host(ip("10.0.0.1")).unwrap().complete,
            "down hosts are done"
        );
        assert_eq!((r.hosts_up(), r.open_ports()), (1, 3));
    }

    #[test]
    fn vuln_check_and_data_are_kept() {
        let mut b = ReportBuilder::new(config(), 1_000);
        let data = VulnData {
            built_at: "2026-11-01".into(),
            cve_count: 7,
            source: "test".into(),
        };
        b.apply(&ScanEvent::VulnData(data.clone()));
        assert_eq!(b.vuln_data(), Some(&data));
        host(&mut b, "10.0.0.2", HostState::Up);
        port(&mut b, "10.0.0.2", 22, Protocol::Tcp);
        let check = |port| ScanEvent::VulnCheck {
            ip: ip("10.0.0.2"),
            protocol: Protocol::Tcp,
            port,
            status: rmap_core::VulnCheck::NoProduct,
        };
        b.apply(&check(22));
        b.apply(&check(23)); // no such port
        assert_eq!(b.orphans(), 1);
        let r = b.report();
        assert_eq!(r.vuln_data, Some(data));
        assert_eq!(
            r.hosts[0].ports[0].vuln_check,
            Some(rmap_core::VulnCheck::NoProduct)
        );
    }

    #[test]
    fn service_before_port_is_kept() {
        let mut b = ReportBuilder::new(config(), 0);
        host(&mut b, "10.0.0.2", HostState::Up);
        b.apply(&ScanEvent::Service {
            ip: ip("10.0.0.2"),
            protocol: Protocol::Tcp,
            port: 22,
            service: ssh("8.9"),
        });
        port(&mut b, "10.0.0.2", 22, Protocol::Tcp);
        assert_eq!(b.report().hosts[0].ports[0].service, Some(ssh("8.9")));
    }

    #[test]
    fn later_service_replaces_earlier() {
        let mut b = ReportBuilder::new(config(), 0);
        host(&mut b, "10.0.0.2", HostState::Up);
        port(&mut b, "10.0.0.2", 22, Protocol::Tcp);
        for v in ["8.9", "9.6"] {
            b.apply(&ScanEvent::Service {
                ip: ip("10.0.0.2"),
                protocol: Protocol::Tcp,
                port: 22,
                service: ssh(v),
            });
        }
        assert_eq!(b.report().hosts[0].ports[0].service, Some(ssh("9.6")));
    }

    #[test]
    fn duplicate_port_events_do_not_duplicate() {
        let mut b = ReportBuilder::new(config(), 0);
        host(&mut b, "10.0.0.2", HostState::Up);
        port(&mut b, "10.0.0.2", 22, Protocol::Tcp);
        port(&mut b, "10.0.0.2", 22, Protocol::Tcp);
        assert_eq!(b.report().hosts[0].ports.len(), 1);
    }

    #[test]
    fn orphan_events_are_counted_not_stored() {
        let mut b = ReportBuilder::new(config(), 0);
        port(&mut b, "10.9.9.9", 1, Protocol::Tcp);
        b.apply(&ScanEvent::Service {
            ip: ip("10.9.9.9"),
            protocol: Protocol::Tcp,
            port: 1,
            service: ssh("1"),
        });
        b.apply(&ScanEvent::HostDone {
            ip: ip("10.9.9.9"),
            closed: 0,
            filtered: 0,
            elapsed: Duration::ZERO,
        });
        assert_eq!(b.orphans(), 3);
        assert!(b.report().hosts.is_empty());
    }

    #[test]
    fn mac_events_fill_mac_and_vendor() {
        let mut b = ReportBuilder::new(config(), 0);
        host(&mut b, "10.0.0.2", HostState::Up);
        host(&mut b, "10.0.0.3", HostState::Up);
        let mac = |s: &str| s.parse::<rmap_core::MacAddr>().unwrap();
        b.apply(&ScanEvent::Mac {
            ip: ip("10.0.0.2"),
            mac: mac("00:11:32:aa:bb:cc"),
        });
        b.apply(&ScanEvent::Mac {
            ip: ip("10.0.0.3"),
            mac: mac("da:11:32:aa:bb:cc"),
        });
        b.apply(&ScanEvent::Mac {
            ip: ip("10.9.9.9"),
            mac: mac("00:11:32:aa:bb:cc"),
        });
        let r = b.report();
        let h = r.host(ip("10.0.0.2")).unwrap();
        assert_eq!(h.mac, Some(mac("00:11:32:aa:bb:cc")));
        assert_eq!(h.vendor.as_deref(), Some("Synology"));
        let h = r.host(ip("10.0.0.3")).unwrap();
        assert!(
            h.mac.is_some() && h.vendor.is_none(),
            "randomised: no vendor"
        );
        assert_eq!(b.orphans(), 1);
    }

    #[test]
    fn hostnames_fill_names_and_an_empty_hostname() {
        use rmap_core::{HostName, NameSource};
        let mut b = ReportBuilder::new(config(), 0);
        host(&mut b, "10.0.0.2", HostState::Up);
        b.apply(&ScanEvent::Host {
            ip: ip("10.0.0.3"),
            hostname: Some("typed.lan".into()),
            state: HostState::Up,
            rtt: None,
        });
        let names = vec![
            HostName::new("pc.corp.lan", NameSource::Dns).unwrap(),
            HostName::new("PC", NameSource::Netbios).unwrap(),
        ];
        for addr in ["10.0.0.2", "10.0.0.3", "10.9.9.9"] {
            b.apply(&ScanEvent::Hostnames {
                ip: ip(addr),
                names: names.clone(),
            });
        }
        let r = b.report();
        let h = r.host(ip("10.0.0.2")).unwrap();
        assert_eq!(h.hostname.as_deref(), Some("pc.corp.lan"));
        assert_eq!(h.names, names);
        let h = r.host(ip("10.0.0.3")).unwrap();
        assert_eq!(h.hostname.as_deref(), Some("typed.lan"), "typed name kept");
        assert_eq!(h.names.len(), 2);
        assert_eq!(b.orphans(), 1);
    }

    #[test]
    fn stopped_and_failed_scans() {
        let mut b = ReportBuilder::new(config(), 10_000);
        b.mark_stopped(12_000);
        b.apply(&ScanEvent::Finished {
            elapsed: Duration::from_secs(9),
        });
        let r = b.report();
        assert_eq!(r.status, RunStatus::Stopped, "a late Finished doesn't win");
        assert_eq!(r.finished_ms, Some(12_000));

        let mut b = ReportBuilder::new(config(), 10_000);
        b.mark_failed(5); // clock went backwards
        b.mark_stopped(20_000);
        let r = b.report();
        assert_eq!(r.status, RunStatus::Failed, "the first ending sticks");
        assert_eq!(r.finished_ms, Some(10_000));
        assert!(r.summary().ends_with("failed"));
    }
}
