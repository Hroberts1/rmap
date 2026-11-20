//! JSON export and import.

use rmap_core::{PortState, Protocol, VulnCheck, VulnSeverity};
use serde::Serialize;

use crate::exposure::{self, Finding, Severity};
use crate::model::{FORMAT_VERSION, ScanReport};

/// What the file holds: the report, plus a `summary` and `findings`
/// derived from it. Both are recomputed on every write and ignored on
/// read, so they never go stale and older files load unchanged.
#[derive(Serialize)]
struct Document<'a> {
    #[serde(flatten)]
    report: &'a ScanReport,
    summary: Summary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    findings: Vec<Finding>,
}

/// Scan-level counts for machine ingestion. Field names are a contract:
/// add fields, don't rename them (see the README).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub hosts_scanned: usize,
    pub hosts_up: usize,
    /// Ports in state `open` (not `open|filtered`).
    pub open_ports: usize,
    pub open_ports_by_protocol: ByProtocol,
    pub cve_check: CveCoverage,
    pub cves_by_severity: CveCounts,
    pub findings_by_severity: FindingCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ByProtocol {
    pub tcp: usize,
    pub udp: usize,
}

/// Ports per CVE check status; `not_run` counts open ports matching never
/// looked at (matching off, or no service detected).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CveCoverage {
    pub checked: usize,
    pub version_hidden: usize,
    pub no_product: usize,
    pub not_covered: usize,
    pub no_database: usize,
    pub not_run: usize,
}

/// Potential CVE matches (one per CVE per port).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CveCounts {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    /// Matches on CISA's Known Exploited Vulnerabilities list.
    pub kev: usize,
}

/// Exposure findings (see [`crate::exposure`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FindingCounts {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// The summary block for `report`, given its exposure findings.
pub fn summary(r: &ScanReport, findings: &[Finding]) -> Summary {
    let open: Vec<_> = r
        .hosts
        .iter()
        .flat_map(|h| &h.ports)
        .filter(|p| p.state == PortState::Open)
        .collect();
    let mut cve_check = CveCoverage::default();
    for p in r.hosts.iter().flat_map(|h| &h.ports) {
        let n = match &p.vuln_check {
            Some(VulnCheck::Checked { .. }) => &mut cve_check.checked,
            Some(VulnCheck::VersionHidden { .. }) => &mut cve_check.version_hidden,
            Some(VulnCheck::NoProduct) => &mut cve_check.no_product,
            Some(VulnCheck::NotCovered { .. }) => &mut cve_check.not_covered,
            Some(VulnCheck::NoDatabase) => &mut cve_check.no_database,
            None if p.state == PortState::Open => &mut cve_check.not_run,
            None => continue,
        };
        *n += 1;
    }
    let mut cves = CveCounts::default();
    for v in r
        .hosts
        .iter()
        .flat_map(|h| &h.ports)
        .flat_map(|p| &p.vulnerabilities)
    {
        cves.total += 1;
        cves.kev += usize::from(v.kev_added.is_some());
        *match v.severity {
            VulnSeverity::Critical => &mut cves.critical,
            VulnSeverity::High => &mut cves.high,
            VulnSeverity::Medium => &mut cves.medium,
            VulnSeverity::Low => &mut cves.low,
        } += 1;
    }
    let mut by_sev = FindingCounts {
        total: findings.len(),
        ..Default::default()
    };
    for f in findings {
        *match f.severity {
            Severity::High => &mut by_sev.high,
            Severity::Medium => &mut by_sev.medium,
            Severity::Low => &mut by_sev.low,
            Severity::Info => &mut by_sev.info,
        } += 1;
    }
    Summary {
        hosts_scanned: r.hosts.len(),
        hosts_up: r.hosts_up(),
        open_ports: open.len(),
        open_ports_by_protocol: ByProtocol {
            tcp: open.iter().filter(|p| p.protocol == Protocol::Tcp).count(),
            udp: open.iter().filter(|p| p.protocol == Protocol::Udp).count(),
        },
        cve_check,
        cves_by_severity: cves,
        findings_by_severity: by_sev,
    }
}

/// The report as pretty-printed JSON, with its `summary` and `findings`.
pub fn to_string(report: &ScanReport) -> serde_json::Result<String> {
    let findings = exposure::findings(report);
    serde_json::to_string_pretty(&Document {
        report,
        summary: summary(report, &findings),
        findings,
    })
}

/// Parse a report, rejecting files written by a newer, incompatible rmap.
pub fn from_str(text: &str) -> Result<ScanReport, String> {
    #[derive(serde::Deserialize)]
    struct Header {
        format_version: Option<u32>,
    }
    let header: Header =
        serde_json::from_str(text).map_err(|e| format!("not an rmap report: {e}"))?;
    match header.format_version {
        None => return Err("not an rmap report: no format_version".into()),
        Some(v) if v > FORMAT_VERSION => {
            return Err(format!(
                "report format {v} is newer than this rmap understands ({FORMAT_VERSION}); upgrade rmap"
            ));
        }
        Some(_) => {}
    }
    let mut report: ScanReport =
        serde_json::from_str(text).map_err(|e| format!("invalid rmap report: {e}"))?;
    // Derived data: recompute, so old files gain groups and a file's own
    // (possibly edited) groups are never trusted.
    crate::devices::assign(&mut report);
    Ok(report)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use rmap_core::{DetectMethod, HostState, PortResult, PortState, Protocol, ScanEvent, Service};

    use super::*;
    use crate::ReportBuilder;
    use crate::builder::tests::{config, ip};

    pub(crate) fn sample() -> ScanReport {
        let mut b = ReportBuilder::new(config(), 1_763_389_805_123);
        b.apply(&ScanEvent::Host {
            ip: ip("10.0.0.2"),
            hostname: Some("db.lan".into()),
            state: HostState::Up,
            rtt: Some(Duration::from_micros(1_234)),
        });
        b.apply(&ScanEvent::Host {
            ip: ip("::1"),
            hostname: None,
            state: HostState::Assumed,
            rtt: None,
        });
        b.apply(&ScanEvent::Port {
            ip: ip("10.0.0.2"),
            result: PortResult::new(
                22,
                Protocol::Tcp,
                PortState::Open,
                Some(Duration::from_micros(900)),
            ),
        });
        b.apply(&ScanEvent::Port {
            ip: ip("10.0.0.2"),
            result: PortResult::new(161, Protocol::Udp, PortState::OpenFiltered, None),
        });
        b.apply(&ScanEvent::Service {
            ip: ip("10.0.0.2"),
            protocol: Protocol::Tcp,
            port: 22,
            service: Service {
                name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: Some("9.6p1".into()),
                info: Some("Ubuntu Linux; protocol 2.0".into()),
                os_hint: Some("Linux".into()),
                cpes: vec!["cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*".into()],
                method: DetectMethod::Probe,
                confidence: 10,
                ..Default::default()
            },
        });
        b.apply(&ScanEvent::HostDone {
            ip: ip("10.0.0.2"),
            closed: 997,
            filtered: 1,
            elapsed: Duration::from_secs(1),
        });
        b.apply(&ScanEvent::Finished {
            elapsed: Duration::from_millis(4_321),
        });
        b.report()
    }

    #[test]
    fn round_trip() {
        let report = sample();
        let text = to_string(&report).unwrap();
        assert!(text.contains("\n  \"format_version\": 1"), "pretty: {text}");
        assert_eq!(from_str(&text).unwrap(), report);
    }

    #[test]
    fn vuln_check_and_data_round_trip() {
        let mut report = crate::summary::tests::fixture();
        report.hosts[0].ports[1].vuln_check = Some(rmap_core::VulnCheck::VersionHidden {
            product: "Net-SNMP".into(),
        });
        let text = to_string(&report).unwrap();
        assert!(text.contains("\"status\": \"version_hidden\""), "{text}");
        assert!(text.contains("\"kev_added\": \"2024-07-15\""), "{text}");
        assert!(text.contains("\"cve_count\": 245000"), "{text}");
        assert_eq!(from_str(&text).unwrap(), report);
        // Absent statuses and data aren't written, so older files look the same.
        let text = to_string(&sample()).unwrap();
        assert!(!text.contains("vuln_check") && !text.contains("vuln_data"));
    }

    #[test]
    fn summary_counts_a_known_report() {
        let mut r = crate::summary::tests::fixture();
        r.hosts.push(crate::exposure::tests::printer());
        let findings = exposure::findings(&r);
        let s = summary(&r, &findings);
        assert_eq!((s.hosts_scanned, s.hosts_up, s.open_ports), (3, 3, 5));
        assert_eq!(s.open_ports_by_protocol, ByProtocol { tcp: 5, udp: 0 });
        assert_eq!(
            s.cve_check,
            CveCoverage {
                checked: 1,
                not_run: 4,
                ..Default::default()
            }
        );
        assert_eq!(
            s.cves_by_severity,
            CveCounts {
                total: 2,
                high: 1,
                medium: 1,
                kev: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            s.findings_by_severity,
            FindingCounts {
                total: 2,
                high: 1,
                medium: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn summary_and_findings_are_written_and_ignored_on_read() {
        let mut r = sample();
        r.hosts.push(crate::exposure::tests::printer());
        let text = to_string(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["summary"]["hosts_up"], 3);
        assert_eq!(v["summary"]["findings_by_severity"]["high"], 1);
        assert_eq!(v["summary"]["cve_check"]["not_run"], 5, "ssh + printer");
        assert_eq!(v["findings"][0]["id"], "telnet");
        assert_eq!(v["findings"][0]["severity"], "high");
        assert_eq!(v["findings"][0]["port"], 23);
        assert_eq!(v["findings"][0]["protocol"], "tcp");
        assert_eq!(from_str(&text).unwrap(), r);
        // No findings: no `findings` key, but always a summary.
        let text = to_string(&sample()).unwrap();
        assert!(text.contains("\"summary\"") && !text.contains("\"findings\""));
    }

    #[test]
    fn empty_report_round_trips() {
        let mut report = ScanReport::new(config(), 0);
        crate::devices::assign(&mut report);
        assert_eq!(from_str(&to_string(&report).unwrap()).unwrap(), report);
    }

    #[test]
    fn device_groups_round_trip_and_old_files_still_load() {
        let mut b = ReportBuilder::new(config(), 0);
        for a in ["10.0.0.2", "10.0.0.3"] {
            b.apply(&ScanEvent::Host {
                ip: ip(a),
                hostname: None,
                state: HostState::Up,
                rtt: None,
            });
            b.apply(&ScanEvent::Mac {
                ip: ip(a),
                mac: "00:11:32:aa:bb:cc".parse().unwrap(),
            });
        }
        let report = b.report();
        assert_eq!(report.devices, Some(1));
        let g = report.hosts[1].device_group.as_ref().unwrap();
        assert_eq!(g.members, [ip("10.0.0.2"), ip("10.0.0.3")]);
        let text = to_string(&report).unwrap();
        assert!(text.contains("\"device_group\": {"), "{text}");
        assert!(text.contains("same MAC"), "{text}");
        assert_eq!(from_str(&text).unwrap(), report);

        // Saved before grouping existed: the groups are recomputed on load.
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v.as_object_mut().unwrap().remove("devices");
        for h in v["hosts"].as_array_mut().unwrap() {
            h.as_object_mut().unwrap().remove("device_group");
        }
        assert_eq!(from_str(&v.to_string()).unwrap(), report);
        // A file's own groups aren't trusted, even malformed ones.
        v["hosts"][0]["device_group"] = serde_json::json!({"id": 9, "members": [], "reasons": []});
        assert_eq!(from_str(&v.to_string()).unwrap(), report);
    }

    #[test]
    fn unknown_fields_are_ignored_and_missing_optionals_default() {
        let mut v: serde_json::Value =
            serde_json::from_str(&to_string(&sample()).unwrap()).unwrap();
        v["future_field"] = serde_json::json!({"x": 1});
        let host = &mut v["hosts"][0];
        host.as_object_mut().unwrap().remove("ports");
        host.as_object_mut().unwrap().remove("hostname");
        // Reports saved before exclusions and the rate cap existed.
        let config = v["config"].as_object_mut().unwrap();
        config.remove("exclude");
        config.remove("max_rate");
        let r = from_str(&v.to_string()).unwrap();
        assert!(r.hosts[0].ports.is_empty() && r.hosts[0].hostname.is_none());
        assert!(r.config.exclude.is_empty() && r.config.max_rate.is_none());
    }

    #[test]
    fn mac_round_trips_and_old_files_still_load() {
        let mut report = sample();
        let text = to_string(&report).unwrap();
        assert!(!text.contains("\"mac\""), "absent MACs aren't written");
        report.hosts[0].mac = Some("00:11:32:aa:bb:cc".parse().unwrap());
        report.hosts[0].vendor = Some("Synology".into());
        let text = to_string(&report).unwrap();
        assert!(text.contains("\"mac\": \"00:11:32:aa:bb:cc\""), "{text}");
        assert_eq!(from_str(&text).unwrap(), report);

        let bad = text.replace("00:11:32:aa:bb:cc", "00:11:32:aa:bb");
        assert!(from_str(&bad).unwrap_err().contains("invalid MAC"));
    }

    #[test]
    fn rejects_newer_and_foreign_files() {
        let mut v: serde_json::Value =
            serde_json::from_str(&to_string(&sample()).unwrap()).unwrap();
        v["format_version"] = (FORMAT_VERSION + 1).into();
        assert!(from_str(&v.to_string()).unwrap_err().contains("newer"));
        assert!(from_str("{}").unwrap_err().contains("format_version"));
        assert!(from_str("not json").is_err());
        assert!(from_str("").is_err());
        assert!(from_str("[1,2]").is_err());
        assert!(from_str(r#"{"format_version":1}"#).is_err());
    }
}
