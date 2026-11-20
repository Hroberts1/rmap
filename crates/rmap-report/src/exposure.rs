//! Exposure findings: risky things a scan shows that aren't CVEs, such as
//! Telnet on a printer, a database reachable from the LAN, an expired
//! certificate, or the one workstation with SMB open when its peers have
//! none. Computed from a finished [`ScanReport`] by pure rule functions: no
//! network traffic, no clock (certificate dates are judged against the
//! scan's start), so a saved scan always reads the same.
//!
//! Adding a rule: a simple "this port is risky" rule is one line in
//! [`PORT_RULES`]; anything else is a function added to [`RULES`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rmap_core::{DetectMethod, PortResult, PortState, Protocol};
use serde::Serialize;

use crate::model::{HostReport, ScanReport};
use crate::summary::one_line;

/// How much a finding matters, least first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// Worst first, for listing and counting.
    pub const ALL: [Severity; 4] = [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// One exposure finding. Text fields are single-line with control
/// characters removed, but may contain scanned text (service names,
/// hostnames), so exporters still escape them for their format.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// Stable rule id, e.g. `telnet`, `cert-expired`, `peer-outlier`.
    pub id: &'static str,
    pub severity: Severity,
    pub ip: IpAddr,
    /// The port the finding is about; `None` for host-wide findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    pub title: String,
    pub detail: String,
}

impl Finding {
    fn on(id: &'static str, severity: Severity, ip: IpAddr, p: &PortResult) -> Finding {
        Finding {
            id,
            severity,
            ip,
            port: Some(p.port),
            protocol: Some(p.protocol),
            title: String::new(),
            detail: String::new(),
        }
    }

    /// `10.0.0.5:23/tcp`, or just the address for host-wide findings.
    pub fn place(&self) -> String {
        match (self.port, self.protocol) {
            (Some(port), Some(proto)) => {
                format!(
                    "{}/{}",
                    std::net::SocketAddr::new(self.ip, port),
                    proto.as_str()
                )
            }
            _ => self.ip.to_string(),
        }
    }
}

/// Every rule, run in order.
const RULES: &[fn(&ScanReport, &mut Vec<Finding>)] =
    &[port_rules, snmp_community, certificates, peer_outliers];

/// Every finding in the report, worst first, then by address and port.
pub fn findings(r: &ScanReport) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in RULES {
        rule(r, &mut out);
    }
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.ip.cmp(&b.ip))
            .then(a.port.cmp(&b.port))
            .then(a.id.cmp(b.id))
    });
    out
}

/// Findings per severity, in [`Severity::ALL`] order.
pub fn counts(findings: &[Finding]) -> [usize; 4] {
    let mut out = [0; 4];
    for f in findings {
        out[Severity::ALL
            .iter()
            .position(|s| *s == f.severity)
            .unwrap_or(3)] += 1;
    }
    out
}

/// `3 (high 1, medium 2)`, or `none`.
pub fn severity_line(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "none".into();
    }
    let parts: Vec<String> = Severity::ALL
        .iter()
        .zip(counts(findings))
        .filter(|(_, n)| *n > 0)
        .map(|(s, n)| format!("{} {n}", s.as_str()))
        .collect();
    format!("{} ({})", findings.len(), parts.join(", "))
}

// ---------------------------------------------------------- port rules ---

/// A service that is risky just by being reachable.
struct PortRule {
    id: &'static str,
    severity: Severity,
    /// Service names detection gives it (probe or banner match).
    names: &'static [&'static str],
    /// TCP ports it is assumed to be on when detection couldn't tell.
    ports: &'static [u16],
    title: &'static str,
    why: &'static str,
    /// Port-number guesses on a printer don't count: printers reuse
    /// "database" ports for their own web services (Zebra on 9200).
    not_on_printers: bool,
}

const fn rule(
    id: &'static str,
    severity: Severity,
    names: &'static [&'static str],
    ports: &'static [u16],
    title: &'static str,
    why: &'static str,
) -> PortRule {
    PortRule {
        id,
        severity,
        names,
        ports,
        title,
        why,
        not_on_printers: false,
    }
}

const fn database(
    id: &'static str,
    severity: Severity,
    names: &'static [&'static str],
    ports: &'static [u16],
    title: &'static str,
) -> PortRule {
    PortRule {
        not_on_printers: true,
        ..rule(
            id,
            severity,
            names,
            ports,
            title,
            "Databases should only be reachable from the application servers that use them.",
        )
    }
}

use Severity::{High, Low, Medium};

const NO_AUTH: &str = "It has no authentication by default.";

static PORT_RULES: &[PortRule] = &[
    // Plaintext logins and management.
    rule(
        "ftp",
        Medium,
        &["ftp"],
        &[21],
        "FTP (plaintext login)",
        "FTP sends user names, passwords and files unencrypted. Disable it or use SFTP/FTPS.",
    ),
    rule(
        "telnet",
        High,
        &["telnet"],
        &[23],
        "Telnet (plaintext remote login)",
        "Telnet sends the login and the whole session unencrypted. Disable it and use SSH.",
    ),
    rule(
        "pop3",
        Low,
        &["pop3"],
        &[110],
        "POP3 without TLS",
        "Mail logins can cross the network unencrypted unless STARTTLS is required. Prefer POP3S (995).",
    ),
    rule(
        "imap",
        Low,
        &["imap"],
        &[143],
        "IMAP without TLS",
        "Mail logins can cross the network unencrypted unless STARTTLS is required. Prefer IMAPS (993).",
    ),
    // Remote administration.
    rule(
        "rdp",
        Medium,
        &["rdp"],
        &[3389],
        "Remote Desktop reachable",
        "RDP is a common ransomware entry point. Limit it to admin hosts or a VPN and require NLA.",
    ),
    rule(
        "vnc",
        Medium,
        &["vnc"],
        &[5900, 5901, 5902, 5903],
        "VNC reachable",
        "VNC often has weak or no authentication and may not encrypt. Limit it to admin hosts or tunnel it.",
    ),
    rule(
        "winrm-http",
        Low,
        &["winrm"],
        &[5985],
        "WinRM over HTTP reachable",
        "Remote PowerShell management is reachable. Limit it to admin hosts; prefer HTTPS (5986).",
    ),
    // Databases.
    database("mssql", Medium, &["mssql"], &[1433], "SQL Server reachable"),
    database("mysql", Medium, &["mysql"], &[3306], "MySQL reachable"),
    database(
        "postgresql",
        Medium,
        &["postgresql", "postgres"],
        &[5432],
        "PostgreSQL reachable",
    ),
    PortRule {
        why: NO_AUTH,
        ..database("redis", High, &["redis"], &[6379], "Redis reachable")
    },
    PortRule {
        why: NO_AUTH,
        ..database("mongodb", High, &["mongodb"], &[27017], "MongoDB reachable")
    },
    PortRule {
        why: NO_AUTH,
        ..database(
            "memcached",
            High,
            &["memcached"],
            &[11211],
            "Memcached reachable",
        )
    },
    PortRule {
        why: NO_AUTH,
        ..database(
            "elasticsearch",
            High,
            &["elasticsearch"],
            &[9200],
            "Elasticsearch reachable",
        )
    },
];

/// Whether a detected port is the rule's service.
fn port_matches(rule: &PortRule, h: &HostReport, p: &PortResult) -> bool {
    if p.state != PortState::Open {
        return false;
    }
    let guess = match &p.service {
        // Accepted but answered nothing: no evidence it is the service
        // (tarpits and honeypots do this on every port).
        Some(s) if s.is_silent() => return false,
        Some(s) if s.method != DetectMethod::PortTable => {
            return rule.names.contains(&s.name.as_str());
        }
        _ => p.protocol == Protocol::Tcp && rule.ports.contains(&p.port),
    };
    guess && !(rule.not_on_printers && is_printer(h))
}

fn port_rules(r: &ScanReport, out: &mut Vec<Finding>) {
    for h in r.hosts.iter().filter(|h| h.is_up()) {
        for p in &h.ports {
            for rule in PORT_RULES.iter().filter(|rule| port_matches(rule, h, p)) {
                let seen = seen_as(p);
                out.push(Finding {
                    title: rule.title.into(),
                    detail: format!("{} Seen as: {seen}.", rule.why),
                    ..Finding::on(rule.id, rule.severity, h.ip, p)
                });
            }
        }
    }
}

/// `telnet`, `ftp? (port-number guess)`, or `mysql MySQL 8.0.36`.
fn seen_as(p: &PortResult) -> String {
    let Some(s) = &p.service else {
        return format!("port {} open, service not identified", p.port);
    };
    let mut text = s.display_name();
    if let Some(v) = s.version_label() {
        text.push(' ');
        text.push_str(&v);
    }
    if s.method == DetectMethod::PortTable {
        text.push_str(" (port-number guess)");
    }
    one_line(&text)
}

/// Looks like a printer: a raw print port is open, or something names a
/// print server.
// shortcut: text heuristics; switch to the host `tags` detection adds once
// they carry a printer label.
fn is_printer(h: &HostReport) -> bool {
    let text_says = |t: &str| {
        let t = t.to_ascii_lowercase();
        ["zebra", "zbr-", "printer", "jetdirect"]
            .iter()
            .any(|w| t.contains(w))
    };
    h.vendor.as_deref().is_some_and(text_says)
        || h.ports.iter().any(|p| {
            (p.state == PortState::Open && matches!(p.port, 515 | 9100..=9107))
                || p.service.as_ref().is_some_and(|s| {
                    [&s.product, &s.info]
                        .into_iter()
                        .flatten()
                        .any(|t| text_says(t))
                })
        })
}

// ---------------------------------------------------------------- SNMP ---

/// SNMP v1/v2c answered with a community string: anyone who can reach the
/// port and guess it (usually `public`) can read the device's config.
fn snmp_community(r: &ScanReport, out: &mut Vec<Finding>) {
    for h in r.hosts.iter().filter(|h| h.is_up()) {
        for p in &h.ports {
            let Some(s) = p.service.as_ref().filter(|s| s.name == "snmp") else {
                continue;
            };
            let info = s.info.as_deref().unwrap_or_default();
            let Some(version) = ["SNMPv1", "SNMPv2c"]
                .into_iter()
                .find(|v| info.starts_with(v))
            else {
                continue;
            };
            out.push(Finding {
                title: format!("{version} community accepted"),
                detail: format!(
                    "{version} has no encryption and a guessable shared password. \
                     Use SNMPv3, or restrict it to the monitoring server. Reply: {}.",
                    one_line(info)
                ),
                ..Finding::on("snmp-v1-v2c", Medium, h.ip, p)
            });
        }
    }
}

// -------------------------------------------------------- certificates ---

/// Expiring certificates are flagged this many days ahead.
const EXPIRY_WARN_DAYS: i64 = 30;

fn certificates(r: &ScanReport, out: &mut Vec<Finding>) {
    let today = r.started_ms.div_euclid(86_400_000);
    for h in r.hosts.iter().filter(|h| h.is_up()) {
        for p in &h.ports {
            let Some(cert) = p.service.as_ref().and_then(|s| s.cert.as_ref()) else {
                continue;
            };
            let name = cert.subject_cn.as_deref().map_or_else(
                || "certificate".into(),
                |cn| format!("\"{}\"", one_line(cn)),
            );
            let self_signed = if cert.self_signed {
                " (self-signed)"
            } else {
                ""
            };
            let not_after = cert.not_after.as_deref().unwrap_or_default();
            let left = parse_day(not_after).map(|d| d - today);
            let f = match left {
                Some(left) if left < 0 => Finding {
                    title: "Expired TLS certificate".into(),
                    detail: format!(
                        "The {name}{self_signed} certificate expired on {not_after}, \
                         {} days before the scan. Clients will warn or refuse to connect.",
                        -left
                    ),
                    ..Finding::on(
                        "cert-expired",
                        if cert.self_signed { Low } else { Medium },
                        h.ip,
                        p,
                    )
                },
                Some(left @ 0..=EXPIRY_WARN_DAYS) => Finding {
                    title: "TLS certificate expiring soon".into(),
                    detail: format!(
                        "The {name}{self_signed} certificate expires on {not_after}, \
                         {left} days after the scan. Renew it."
                    ),
                    ..Finding::on(
                        "cert-expiring",
                        if cert.self_signed {
                            Severity::Info
                        } else {
                            Low
                        },
                        h.ip,
                        p,
                    )
                },
                _ if cert.self_signed => Finding {
                    title: "Self-signed TLS certificate".into(),
                    detail: format!(
                        "The {name} certificate is self-signed, so clients can't verify \
                         the server. Normal for appliances' admin pages."
                    ),
                    ..Finding::on("cert-self-signed", Severity::Info, h.ip, p)
                },
                _ => continue,
            };
            out.push(f);
        }
    }
}

/// `YYYY-MM-DD` as days since 1970-01-01; `None` unless well-formed.
fn parse_day(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

// ------------------------------------------------------- peer outliers ---

/// A host is only an outlier against at least this many peers without the
/// port, so two odd machines never flag each other.
const MIN_PEERS: usize = 3;

/// Ports that make an outlier worth more than a note.
fn risky(port: u16) -> bool {
    matches!(port, 21 | 23 | 135 | 139 | 445 | 3389 | 5900..=5903 | 5985)
}

/// `OFFICE-PC014.corp.lan` → `office-pc`: the first label up to its first digit.
/// `None` for names with no digit (`lobby`), which don't form fleets.
fn name_prefix(name: &str) -> Option<String> {
    let label = name.split('.').next()?;
    let digit = label.find(|c: char| c.is_ascii_digit())?;
    let prefix = label[..digit].trim_end_matches(['-', '_']);
    (prefix.chars().count() >= 2).then(|| prefix.to_ascii_lowercase())
}

/// Flags a host with open ports most of its peers (hosts named alike, e.g.
/// `WKS01`..`WKS05`) don't have: the one workstation with SMB open.
// shortcut: peers are found by hostname prefix only; grouping by similar
// open-port sets was left out because it flags appliances against each
// other. Add it if fleets without naming conventions need this.
fn peer_outliers(r: &ScanReport, out: &mut Vec<Finding>) {
    let mut groups: BTreeMap<String, Vec<&HostReport>> = BTreeMap::new();
    for h in r.hosts.iter().filter(|h| h.is_up() && h.complete) {
        if let Some(prefix) = h.hostname.as_deref().and_then(name_prefix) {
            groups.entry(prefix).or_default().push(h);
        }
    }
    for (prefix, hosts) in groups {
        let open = |h: &HostReport| -> BTreeSet<(u16, Protocol)> {
            h.ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| (p.port, p.protocol))
                .collect()
        };
        let sets: Vec<_> = hosts.iter().map(|h| open(h)).collect();
        let have = |port: &(u16, Protocol)| sets.iter().filter(|s| s.contains(port)).count();
        for (h, set) in hosts.iter().zip(&sets) {
            let extra: Vec<_> = set
                .iter()
                .filter(|port| {
                    let with = have(port);
                    let without = hosts.len() - with;
                    without >= MIN_PEERS && with < without
                })
                .collect();
            if extra.is_empty() {
                continue;
            }
            let list: Vec<String> = extra
                .iter()
                .map(|(port, proto)| format!("{port}/{}", proto.as_str()))
                .collect();
            // Peers lacking the least unusual of the ports.
            let without = extra
                .iter()
                .map(|p| hosts.len() - have(p))
                .min()
                .unwrap_or(0);
            let peers: Vec<String> = hosts
                .iter()
                .filter(|p| p.ip != h.ip)
                .take(5)
                .map(|p| one_line(p.hostname.as_deref().unwrap_or_default()))
                .collect();
            let more = if hosts.len() - 1 > peers.len() {
                ", …"
            } else {
                ""
            };
            out.push(Finding {
                id: "peer-outlier",
                severity: if extra.iter().any(|(p, _)| risky(*p)) {
                    Medium
                } else {
                    Low
                },
                ip: h.ip,
                port: None,
                protocol: None,
                title: format!("Open ports its peers don't have: {}", list.join(", ")),
                detail: format!(
                    "Peer group: {} hosts named {}* ({}{more}). Each port is closed on at \
                     least {without} of the others; check whether this host needs it.",
                    hosts.len(),
                    one_line(&prefix),
                    peers.join(", "),
                ),
            });
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use rmap_core::{CertInfo, HostState, Service};

    use super::*;
    use crate::builder::tests::{config, ip};

    /// 2026-11-20 12:00 UTC.
    pub(crate) const SCAN_START: i64 = 1_795_176_000_000;

    pub(crate) fn host(addr: &str, name: Option<&str>, ports: Vec<PortResult>) -> HostReport {
        let mut h = HostReport::new(ip(addr), name.map(Into::into), HostState::Up);
        h.ports = ports;
        h.complete = true;
        h
    }

    pub(crate) fn port(n: u16, service: Option<Service>) -> PortResult {
        let mut p = PortResult::new(n, Protocol::Tcp, PortState::Open, None);
        p.service = service;
        p
    }

    pub(crate) fn svc(name: &str, method: DetectMethod, info: Option<&str>) -> Service {
        Service {
            name: name.into(),
            info: info.map(Into::into),
            method,
            ..Default::default()
        }
    }

    pub(crate) fn report(hosts: Vec<HostReport>) -> ScanReport {
        let mut r = ScanReport::new(config(), SCAN_START);
        r.hosts = hosts;
        r
    }

    fn ids(r: &ScanReport) -> Vec<(&'static str, Option<u16>, Severity)> {
        findings(r)
            .into_iter()
            .map(|f| (f.id, f.port, f.severity))
            .collect()
    }

    /// A Zebra-like label printer: FTP with its banner, Telnet, raw print
    /// and a port-number guess of Elasticsearch on 9200.
    pub(crate) fn printer() -> HostReport {
        host(
            "10.9.0.26",
            Some("PRN-0042"),
            vec![
                port(
                    21,
                    Some(svc(
                        "ftp",
                        DetectMethod::PortTable,
                        Some("unrecognised reply: 220 ZBR-12345 Version V1.2.3 ready."),
                    )),
                ),
                port(23, Some(svc("telnet", DetectMethod::Banner, None))),
                port(9100, None),
                port(
                    9200,
                    Some(svc(
                        "elasticsearch",
                        DetectMethod::PortTable,
                        Some("not probed"),
                    )),
                ),
            ],
        )
    }

    #[test]
    fn ftp_and_telnet_on_a_printer_but_no_database_guess() {
        let r = report(vec![printer()]);
        assert_eq!(
            ids(&r),
            [("telnet", Some(23), High), ("ftp", Some(21), Medium)]
        );
        let f = &findings(&r)[1];
        assert!(f.detail.contains("ftp? (port-number guess)"), "{f:?}");
        assert_eq!(f.place(), "10.9.0.26:21/tcp");
    }

    #[test]
    fn elasticsearch_counts_off_printers_and_when_probed() {
        let es = |method| port(9200, Some(svc("elasticsearch", method, Some("not probed"))));
        let r = report(vec![host(
            "10.9.0.1",
            None,
            vec![es(DetectMethod::PortTable)],
        )]);
        assert_eq!(ids(&r), [("elasticsearch", Some(9200), High)]);
        // A real identification counts even on a printer.
        let mut p = printer();
        p.ports[3] = es(DetectMethod::Probe);
        assert!(ids(&report(vec![p])).contains(&("elasticsearch", Some(9200), High)));
    }

    #[test]
    fn silent_or_differently_identified_ports_are_not_flagged() {
        let silent = svc("ftp", DetectMethod::PortTable, Some(rmap_core::SILENT_INFO));
        let r = report(vec![host(
            "10.9.0.2",
            None,
            vec![
                port(21, Some(silent)),
                port(23, Some(svc("http", DetectMethod::Probe, None))),
                port(3306, Some(svc("tls/mysql", DetectMethod::Probe, None))),
                port(3389, None),
            ],
        )]);
        assert_eq!(ids(&r), [("rdp", Some(3389), Medium)]);
        // Telnet found on an unusual port by its banner still counts.
        let r = report(vec![host(
            "10.9.0.3",
            None,
            vec![port(2323, Some(svc("telnet", DetectMethod::Banner, None)))],
        )]);
        assert_eq!(ids(&r), [("telnet", Some(2323), High)]);
    }

    #[test]
    fn snmp_v1_v2c_only_when_detection_says_so() {
        let snmp = |info: &str| {
            let mut p = port(161, Some(svc("snmp", DetectMethod::Probe, Some(info))));
            p.protocol = Protocol::Udp;
            p
        };
        let r = report(vec![host(
            "10.9.0.4",
            None,
            vec![
                snmp("SNMPv2c, community \"public\" accepted: Linux box"),
                snmp("something else"),
            ],
        )]);
        assert_eq!(ids(&r), [("snmp-v1-v2c", Some(161), Medium)]);
        assert_eq!(findings(&r)[0].title, "SNMPv2c community accepted");
    }

    fn tls(not_after: &str, self_signed: bool) -> PortResult {
        let mut s = svc("tls/http", DetectMethod::Probe, None);
        s.cert = Some(CertInfo {
            subject_cn: Some("nas.example.test".into()),
            not_after: Some(not_after.into()),
            self_signed,
            ..Default::default()
        });
        port(443, Some(s))
    }

    #[test]
    fn certificates_are_judged_against_the_scan_start() {
        let cert_findings = |p: PortResult| -> Vec<(&'static str, Severity, String)> {
            findings(&report(vec![host("10.9.0.5", None, vec![p])]))
                .into_iter()
                .map(|f| (f.id, f.severity, f.detail))
                .collect()
        };
        let expired = cert_findings(tls("2026-11-19", false));
        assert_eq!((expired[0].0, expired[0].1), ("cert-expired", Medium));
        assert!(
            expired[0]
                .2
                .contains("expired on 2026-11-19, 1 days before")
        );
        let old_self_signed = cert_findings(tls("2018-12-30", true));
        assert_eq!(
            (old_self_signed[0].0, old_self_signed[0].1),
            ("cert-expired", Low)
        );
        let soon = cert_findings(tls("2026-11-30", false));
        assert_eq!((soon[0].0, soon[0].1), ("cert-expiring", Low));
        assert!(soon[0].2.contains("10 days after the scan"), "{soon:?}");
        assert_eq!(
            cert_findings(tls("2026-11-20", false))[0].0,
            "cert-expiring"
        );
        assert_eq!(
            cert_findings(tls("2027-06-01", true))
                .iter()
                .map(|f| (f.0, f.1))
                .collect::<Vec<_>>(),
            [("cert-self-signed", Severity::Info)]
        );
        assert!(cert_findings(tls("2027-06-01", false)).is_empty());
        // Unparseable dates are no evidence either way.
        assert!(cert_findings(tls("soon", false)).is_empty());
    }

    #[test]
    fn parse_day_matches_known_dates_and_rejects_junk() {
        assert_eq!(parse_day("1970-01-01"), Some(0));
        assert_eq!(parse_day("2000-03-01"), Some(11_017));
        assert_eq!(
            parse_day("2026-11-20"),
            Some(SCAN_START.div_euclid(86_400_000))
        );
        for bad in [
            "",
            "2026-1-20",
            "2026-13-01",
            "2026-00-10",
            "+026-11-20",
            "2026-11-2x",
            "２０２６-11-20",
        ] {
            assert_eq!(parse_day(bad), None, "{bad}");
        }
    }

    fn fleet(n: usize, outlier_ports: &[u16]) -> Vec<HostReport> {
        (0..n)
            .map(|i| {
                let ports = if i == 1 {
                    outlier_ports.iter().map(|p| port(*p, None)).collect()
                } else {
                    vec![]
                };
                host(
                    &format!("10.9.1.{}", i + 10),
                    Some(&format!("WKS{:02}.lan", i)),
                    ports,
                )
            })
            .collect()
    }

    #[test]
    fn one_workstation_with_smb_stands_out_from_its_peers() {
        let r = report(fleet(5, &[135, 139, 445]));
        let all = findings(&r);
        assert_eq!(all.len(), 1, "{all:?}");
        let f = &all[0];
        assert_eq!((f.id, f.severity, f.port), ("peer-outlier", Medium, None));
        assert_eq!(f.ip, ip("10.9.1.11"));
        assert!(f.title.ends_with("135/tcp, 139/tcp, 445/tcp"), "{f:?}");
        assert!(f.detail.contains("5 hosts named wks*"), "{f:?}");
        assert!(
            f.detail.contains("closed on at least 4 of the others"),
            "{f:?}"
        );
        // A harmless extra port is only low.
        assert_eq!(findings(&report(fleet(5, &[8080])))[0].severity, Low);
    }

    #[test]
    fn small_or_split_groups_flag_nothing() {
        assert!(findings(&report(fleet(2, &[445]))).is_empty());
        assert!(findings(&report(fleet(3, &[8080]))).is_empty(), "2 peers");
        // 2 of 5 is still a minority against 3 peers: both are flagged.
        let mut hosts = fleet(5, &[8080]);
        hosts[2].ports = vec![port(8080, None)];
        assert_eq!(findings(&report(hosts)).len(), 2);
        // Half the fleet having it isn't an outlier.
        let mut hosts = fleet(6, &[8080]);
        hosts[2].ports = vec![port(8080, None)];
        hosts[3].ports = vec![port(8080, None)];
        assert!(findings(&report(hosts)).is_empty());
        // An unfinished host can't vouch for what is closed.
        let mut hosts = fleet(4, &[8080]);
        hosts[0].complete = false;
        assert!(findings(&report(hosts)).is_empty());
    }

    #[test]
    fn name_prefixes() {
        assert_eq!(
            name_prefix("OFFICE-PC014.corp.lan").as_deref(),
            Some("office-pc")
        );
        assert_eq!(name_prefix("wks-01").as_deref(), Some("wks"));
        assert_eq!(name_prefix("lobby"), None);
        assert_eq!(name_prefix("50J18"), None);
        assert_eq!(name_prefix("a1"), None);
        assert_eq!(name_prefix("é1"), None);
        assert_eq!(name_prefix(""), None);
    }

    #[test]
    fn hostile_text_is_single_line() {
        let mut p = printer();
        p.ports[1].service.as_mut().unwrap().product = Some("x\n\x1b[2Jy".into());
        p.hostname = Some("WKS01\n\x1b]0;t\x07".into());
        let mut hosts = fleet(4, &[]);
        hosts.push(p);
        for f in findings(&report(hosts)) {
            for t in [&f.title, &f.detail] {
                assert!(!t.chars().any(char::is_control), "{t:?}");
            }
        }
    }

    #[test]
    fn down_hosts_and_closed_ports_are_ignored() {
        let mut h = printer();
        h.state = HostState::Down;
        assert!(findings(&report(vec![h])).is_empty());
        let mut p = port(23, None);
        p.state = PortState::OpenFiltered;
        assert!(findings(&report(vec![host("10.9.0.7", None, vec![p])])).is_empty());
    }

    #[test]
    fn counts_and_line() {
        let r = report(vec![printer()]);
        let all = findings(&r);
        assert_eq!(counts(&all), [1, 1, 0, 0]);
        assert_eq!(severity_line(&all), "2 (high 1, medium 1)");
        assert_eq!(severity_line(&[]), "none");
    }
}
