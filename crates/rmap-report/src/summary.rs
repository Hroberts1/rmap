//! Helpers shared by the client-facing exports (Markdown, CSV, HTML):
//! severity tallies, time formatting, and neutralising scanned text.

use std::net::IpAddr;
use std::time::Duration;

use rmap_core::{PortResult, Protocol, Service, VulnCheck, VulnSeverity, VulnTier, Vulnerability};
use rmap_log::Timestamp;

use crate::model::{HostReport, ScanReport};

/// Note shown wherever findings are listed: matching is by version only.
pub const FINDINGS_NOTE: &str = "Potential findings: CVEs are matched on the detected product \
    version only, so backported fixes and configuration are not taken into account. Matches \
    that need a platform rmap can't verify are listed as conditional, and client-only CVEs \
    are not counted on listening ports. Verify each finding before acting on it.";

/// Severities from worst to least bad, for listing.
pub const SEVERITIES: [VulnSeverity; 4] = [
    VulnSeverity::Critical,
    VulnSeverity::High,
    VulnSeverity::Medium,
    VulnSeverity::Low,
];

/// One finding on one port.
pub struct Finding<'a> {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub vuln: &'a Vulnerability,
    pub tier: VulnTier,
}

impl Finding<'_> {
    /// Counted as a potential finding (not conditional, not client-only).
    pub fn counted(&self) -> bool {
        matches!(self.tier, VulnTier::Potential | VulnTier::UpstreamOnly)
    }
}

/// Counted tiers first, then worst first, then by score, host and port.
fn worse_first(a: &Finding, b: &Finding) -> std::cmp::Ordering {
    a.tier
        .cmp(&b.tier)
        .then(b.vuln.severity.cmp(&a.vuln.severity))
        .then(
            b.vuln
                .score
                .unwrap_or(0.0)
                .total_cmp(&a.vuln.score.unwrap_or(0.0)),
        )
        .then(a.ip.cmp(&b.ip))
        .then(a.port.cmp(&b.port))
        .then(a.vuln.id.cmp(&b.vuln.id))
}

fn port_findings<'a>(ip: IpAddr, p: &'a PortResult) -> impl Iterator<Item = Finding<'a>> {
    p.vulnerabilities.iter().map(move |v| Finding {
        ip,
        port: p.port,
        protocol: p.protocol,
        vuln: v,
        tier: p.vuln_tier(v),
    })
}

/// Every match in the report, counted tiers first, worst first, then by
/// score, host and port.
pub fn findings(r: &ScanReport) -> Vec<Finding<'_>> {
    let mut out: Vec<Finding> = r
        .hosts
        .iter()
        .flat_map(|h| h.ports.iter().flat_map(move |p| port_findings(h.ip, p)))
        .collect();
    out.sort_by(worse_first);
    out
}

/// Every match on one product and version (and distro build).
pub struct Group<'a> {
    /// `OpenSSH 10.2p1`, or the service name when there's no version.
    pub label: String,
    /// Set when the ports are distro builds (`CheckedUpstreamOnly`).
    pub distro: Option<&'a str>,
    /// Counted tiers first, then worst first.
    pub findings: Vec<Finding<'a>>,
}

impl<'a> Group<'a> {
    /// See [`group_line`].
    pub fn line(&self) -> String {
        let ports: std::collections::HashSet<_> = self
            .findings
            .iter()
            .map(|f| (f.ip, f.port, f.protocol))
            .collect();
        group_line(
            &self.label,
            self.distro,
            self.findings.iter().map(|f| f.tier),
            ports.len(),
        )
    }

    /// This group's matches in `tier`, one per CVE id.
    pub fn unique(&self, tier: VulnTier) -> Vec<&Finding<'a>> {
        let mut seen = std::collections::HashSet::new();
        self.findings
            .iter()
            .filter(|f| f.tier == tier && seen.insert(f.vuln.id.as_str()))
            .collect()
    }
}

/// Every match in the report grouped by product and version, worst group
/// first.
pub fn groups(r: &ScanReport) -> Vec<Group<'_>> {
    let mut groups: Vec<Group> = Vec::new();
    for h in &r.hosts {
        for p in h.ports.iter().filter(|p| !p.vulnerabilities.is_empty()) {
            let label = p
                .service
                .as_ref()
                .and_then(Service::version_label)
                .unwrap_or_else(|| service_name(p));
            let distro = match &p.vuln_check {
                Some(VulnCheck::CheckedUpstreamOnly { distro, .. }) => Some(distro.as_str()),
                _ => None,
            };
            let i = match groups
                .iter()
                .position(|g| g.label == label && g.distro == distro)
            {
                Some(i) => i,
                None => {
                    groups.push(Group {
                        label,
                        distro,
                        findings: Vec::new(),
                    });
                    groups.len() - 1
                }
            };
            groups[i].findings.extend(port_findings(h.ip, p));
        }
    }
    for g in &mut groups {
        g.findings.sort_by(worse_first);
    }
    groups.sort_by(|a, b| worse_first(&a.findings[0], &b.findings[0]));
    groups
}

/// `OpenSSH 10.2p1: 29 potential (upstream match; Ubuntu build) · 3
/// conditional (platform not verified) · 8 client-only, not counted · 2
/// ports`, for a group of matches with these tiers. Unescaped. Shared
/// with the TUI's Vulns tab.
pub fn group_line(
    label: &str,
    distro: Option<&str>,
    tiers: impl Iterator<Item = VulnTier>,
    ports: usize,
) -> String {
    let (mut counted, mut conditional, mut client) = (0, 0, 0);
    for t in tiers {
        match t {
            VulnTier::Potential | VulnTier::UpstreamOnly => counted += 1,
            VulnTier::Conditional => conditional += 1,
            VulnTier::ClientOnly => client += 1,
        }
    }
    let mut s = format!("{label}: {counted} potential");
    if let Some(d) = distro {
        s.push_str(&format!(" (upstream match; {d} build)"));
    }
    if conditional > 0 {
        s.push_str(&format!(
            " · {conditional} conditional (platform not verified)"
        ));
    }
    if client > 0 {
        s.push_str(&format!(" · {client} client-only, not counted"));
    }
    let plural = if ports == 1 { "" } else { "s" };
    s.push_str(&format!(" · {ports} port{plural}"));
    s
}

/// `3 conditional, 9 client-only`: matches left out of the counts, or
/// `None` when there are none.
pub fn not_counted_line(r: &ScanReport) -> Option<String> {
    let all = findings(r);
    let n = |tier| all.iter().filter(|f| f.tier == tier).count();
    let parts: Vec<String> = [
        (n(VulnTier::Conditional), "conditional"),
        (n(VulnTier::ClientOnly), "client-only"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// Counted findings per severity, in [`SEVERITIES`] order.
pub fn severity_counts(r: &ScanReport) -> [usize; 4] {
    let mut counts = [0; 4];
    for f in findings(r).iter().filter(|f| f.counted()) {
        counts[SEVERITIES
            .iter()
            .position(|s| *s == f.vuln.severity)
            .unwrap_or(3)] += 1;
    }
    counts
}

/// `3 (critical 1, high 2)`, or `none`.
pub fn severity_line(r: &ScanReport) -> String {
    let counts = severity_counts(r);
    let total: usize = counts.iter().sum();
    if total == 0 {
        return "none".into();
    }
    let parts: Vec<String> = SEVERITIES
        .iter()
        .zip(counts)
        .filter(|(_, n)| *n > 0)
        .map(|(s, n)| format!("{} {n}", s.as_str()))
        .collect();
    format!("{total} ({})", parts.join(", "))
}

/// The worst counted finding's severity.
pub fn worst(p: &PortResult) -> Option<VulnSeverity> {
    p.counted_vulns().map(|v| v.severity).max()
}

/// `actively exploited (CISA KEV, added 2024-07-01)` for a CVE on CISA's
/// Known Exploited Vulnerabilities list, unless the match is conditional
/// or client-only. Unescaped.
pub fn kev_note(v: &Vulnerability) -> Option<String> {
    v.kev_added
        .as_ref()
        .filter(|_| v.condition.is_none() && !v.client_only)
        .map(|d| format!("actively exploited (CISA KEV, added {d})"))
}

/// `4 of 65 open ports checked`, said up front so a short findings list
/// isn't read as a clean network; `None` when matching never ran.
pub fn coverage_line(r: &ScanReport) -> Option<String> {
    if checked_ports(r) == 0 {
        return None;
    }
    let checked = ports(r)
        .filter(|p| p.vuln_check.as_ref().is_some_and(|c| !c.is_unchecked()))
        .count();
    Some(format!(
        "{checked} of {} open ports checked",
        r.open_ports()
    ))
}

/// `built 2026-11-01, 245000 CVEs (NVD)`; `none available` when matching
/// ran without a database; `None` when matching never ran. Unescaped.
pub fn vuln_data_line(r: &ScanReport) -> Option<String> {
    match &r.vuln_data {
        Some(d) => Some(format!(
            "built {}, {} CVEs ({})",
            d.built_at.get(..10).unwrap_or(&d.built_at),
            d.cve_count,
            d.source
        )),
        None if checked_ports(r) > 0 => Some("none available".into()),
        None => None,
    }
}

/// `(unchecked, total)`: ports with a CVE check status, and how many of
/// them could not be checked (version unknown, no product, no data).
pub fn unchecked_counts(r: &ScanReport) -> (usize, usize) {
    let unchecked = ports(r)
        .filter(|p| p.vuln_check.as_ref().is_some_and(|c| c.is_unchecked()))
        .count();
    (unchecked, checked_ports(r))
}

/// What to say when no CVE matched: never just "none" if some ports
/// couldn't be checked.
pub fn no_findings_text(r: &ScanReport) -> String {
    match unchecked_counts(r) {
        _ if !r.config.service_detection => {
            "Service detection was off, so no CVE matching was done.".into()
        }
        (0, _) => "No potential CVEs matched the detected services.".into(),
        (n, total) => format!(
            "No potential CVEs matched, but {n} of {total} ports could not be checked \
             (see each port's CVE check); that is not the same as no vulnerabilities."
        ),
    }
}

fn ports(r: &ScanReport) -> impl Iterator<Item = &PortResult> {
    r.hosts.iter().flat_map(|h| &h.ports)
}

fn checked_ports(r: &ScanReport) -> usize {
    ports(r).filter(|p| p.vuln_check.is_some()).count()
}

/// `OpenSSH 9.6p1 (Ubuntu Linux)`, from whatever detection found.
pub fn version_text(p: &PortResult) -> String {
    let Some(s) = &p.service else {
        return String::new();
    };
    let mut parts: Vec<&str> = [&s.product, &s.version]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let info = s.info.as_ref().map(|i| format!("({i})"));
    parts.extend(info.as_deref());
    parts.join(" ")
}

/// Service name for people; a port-number guess ends in `?`.
pub fn service_name(p: &PortResult) -> String {
    p.service
        .as_ref()
        .map_or_else(String::new, Service::display_name)
}

/// `10.0.0.2 (db.lan)`.
pub fn host_label(h: &HostReport) -> String {
    match &h.hostname {
        Some(name) => format!("{} ({name})", h.ip),
        None => h.ip.to_string(),
    }
}

/// `2026-11-17 14:30:05 UTC`.
pub fn utc(ms: i64) -> String {
    let t = Timestamp::from_unix_millis(ms);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// `4.3 s`, `2 min 05 s`, `1 h 02 min`.
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{:.1} s", d.as_secs_f64()),
        60..3600 => format!("{} min {:02} s", s / 60, s % 60),
        _ => format!("{} h {:02} min", s / 3600, s % 3600 / 60),
    }
}

/// Scanned text with anything that could act on a terminal or reorder
/// text replaced: control characters (escape sequences included) and
/// bidirectional overrides become U+FFFD. `keep` lists controls to leave.
pub fn neutralise(s: &str, keep: &[char]) -> String {
    s.chars()
        .map(|c| {
            let bidi = matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
            if (c.is_control() && !keep.contains(&c)) || bidi {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Single-line scanned text: line breaks and tabs become spaces, other
/// controls U+FFFD.
pub fn one_line(s: &str) -> String {
    neutralise(&s.replace(['\r', '\n', '\t'], " "), &[])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::json::tests::sample;

    fn vuln(id: &str, severity: VulnSeverity, score: f32, summary: &str) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            summary: summary.into(),
            severity,
            score: Some(score),
            published: Some("2024-07-01".into()),
            kev_added: None,
            condition: None,
            client_only: false,
        }
    }

    /// The JSON sample with findings (one on CISA's KEV list) and a CVE
    /// check status on its SSH port, and the CVE data it was matched with.
    pub(crate) fn fixture() -> ScanReport {
        let mut r = sample();
        r.vuln_data = Some(rmap_core::VulnData {
            built_at: "2025-11-01T03:00:00Z".into(),
            cve_count: 245_000,
            source: "NVD + CISA KEV".into(),
        });
        r.hosts[0].ports[0].vuln_check = Some(rmap_core::VulnCheck::Checked {
            product: "OpenSSH".into(),
            version: "9.6p1".into(),
            matches: 2,
        });
        r.hosts[0].ports[0].vulnerabilities = vec![
            vuln(
                "CVE-2023-51385",
                VulnSeverity::Medium,
                6.5,
                "Shell metacharacters in user names may be expanded.",
            ),
            vuln(
                "CVE-2024-6387",
                VulnSeverity::High,
                8.1,
                "Signal handler race condition (regreSSHion).",
            ),
        ];
        r.hosts[0].ports[0].vulnerabilities[1].kev_added = Some("2024-07-15".into());
        r
    }

    /// Scanned strings an attacker-controlled device could return.
    pub(crate) const HOSTILE: &str = "=cmd|' /C calc'!A1 <script>alert(1)</script> | a,\"b\"\n\x1b[31mred\x1b]0;title\x07 \u{202E}gpj.exe";

    pub(crate) fn hostile() -> ScanReport {
        let mut r = fixture();
        r.config.targets = HOSTILE.into();
        r.hosts[0].hostname = Some(HOSTILE.into());
        let p = &mut r.hosts[0].ports[0];
        let s = p.service.as_mut().unwrap();
        s.name = HOSTILE.into();
        s.product = Some(HOSTILE.into());
        s.version = Some("@SUM(1+1)".into());
        s.info = Some("-2+3".into());
        p.vulnerabilities[0].summary = HOSTILE.into();
        p.vulnerabilities[0].kev_added = Some(HOSTILE.into());
        p.vuln_check = Some(rmap_core::VulnCheck::NotCovered {
            product: HOSTILE.into(),
        });
        let data = r.vuln_data.as_mut().unwrap();
        data.built_at = HOSTILE.into();
        data.source = HOSTILE.into();
        r
    }

    #[test]
    fn unchecked_ports_are_counted_and_never_read_as_clean() {
        let mut r = sample();
        assert_eq!(unchecked_counts(&r), (0, 0));
        assert_eq!(vuln_data_line(&r), None, "matching never ran");
        r.hosts[0].ports[0].vuln_check = Some(rmap_core::VulnCheck::NoDatabase);
        assert_eq!(unchecked_counts(&r), (1, 1));
        assert_eq!(vuln_data_line(&r).as_deref(), Some("none available"));
        assert!(no_findings_text(&r).contains("1 of 1 ports could not be checked"));
        let r = fixture();
        assert_eq!(unchecked_counts(&r), (0, 1));
        assert_eq!(
            vuln_data_line(&r).as_deref(),
            Some("built 2025-11-01, 245000 CVEs (NVD + CISA KEV)")
        );
        let kev = kev_note(&r.hosts[0].ports[0].vulnerabilities[1]);
        assert_eq!(
            kev.as_deref(),
            Some("actively exploited (CISA KEV, added 2024-07-15)")
        );
    }

    /// Compare `actual` with `tests/fixtures/<name>`. After an intended
    /// format change, regenerate with
    /// `RMAP_UPDATE_SNAPSHOTS=1 cargo test -p rmap-report` and review the diff.
    pub(crate) fn snapshot(name: &str, actual: &str) {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os("RMAP_UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(&path, actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap();
        // Git may check fixtures out with CRLF; CSV is CRLF by design.
        assert_eq!(actual.replace("\r\n", "\n"), expected.replace("\r\n", "\n"));
    }

    #[test]
    fn tiers_group_and_count_apart() {
        let mut r = fixture();
        let p = &mut r.hosts[0].ports[0];
        p.vuln_check = Some(VulnCheck::CheckedUpstreamOnly {
            product: "OpenSSH".into(),
            version: "9.6p1".into(),
            matches: 1,
            distro: "Ubuntu".into(),
        });
        // regreSSHion (on KEV) needs a platform; another is client-only.
        p.vulnerabilities[1].condition = Some("musl-libc:musl".into());
        let mut client = vuln("CVE-2026-60002", VulnSeverity::Critical, 9.4, "ssh client");
        client.client_only = true;
        p.vulnerabilities.push(client);
        assert_eq!(kev_note(&p.vulnerabilities[1]), None);
        assert_eq!(severity_line(&r), "1 (medium 1)");
        assert_eq!(worst(&r.hosts[0].ports[0]), Some(VulnSeverity::Medium));
        assert_eq!(
            not_counted_line(&r).as_deref(),
            Some("1 conditional, 1 client-only")
        );
        let groups = groups(&r);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].line(),
            "OpenSSH 9.6p1: 1 potential (upstream match; Ubuntu build) · 1 conditional \
             (platform not verified) · 1 client-only, not counted · 1 port"
        );
        assert_eq!(
            coverage_line(&r).as_deref(),
            Some("1 of 1 open ports checked")
        );
        assert_eq!(coverage_line(&sample()), None);
    }

    #[test]
    fn findings_sort_worst_first() {
        let r = fixture();
        let ids: Vec<&str> = findings(&r).iter().map(|f| f.vuln.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2024-6387", "CVE-2023-51385"]);
        assert_eq!(severity_counts(&r), [0, 1, 1, 0]);
        assert_eq!(severity_line(&r), "2 (high 1, medium 1)");
        assert_eq!(severity_line(&sample()), "none");
        assert_eq!(worst(&r.hosts[0].ports[0]), Some(VulnSeverity::High));
        assert_eq!(worst(&r.hosts[0].ports[1]), None);
    }

    #[test]
    fn text_helpers() {
        let r = fixture();
        assert_eq!(
            version_text(&r.hosts[0].ports[0]),
            "OpenSSH 9.6p1 (Ubuntu Linux; protocol 2.0)"
        );
        assert_eq!(version_text(&r.hosts[0].ports[1]), "");
        assert_eq!(host_label(&r.hosts[0]), "10.0.0.2 (db.lan)");
        assert_eq!(duration(Duration::from_millis(4_321)), "4.3 s");
        assert_eq!(duration(Duration::from_secs(125)), "2 min 05 s");
        assert_eq!(duration(Duration::from_secs(3_720)), "1 h 02 min");
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn neutralise_removes_escapes_and_bidi() {
        assert_eq!(
            one_line("a\x1b[31mb\nc\u{202E}d\u{85}"),
            "a\u{FFFD}[31mb c\u{FFFD}d\u{FFFD}"
        );
        assert_eq!(neutralise("a\nb\x07", &['\n']), "a\nb\u{FFFD}");
        assert!(!one_line(HOSTILE).chars().any(char::is_control));
    }
}
