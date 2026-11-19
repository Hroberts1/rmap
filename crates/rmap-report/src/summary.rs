//! Helpers shared by the client-facing exports (Markdown, CSV, HTML):
//! severity tallies, time formatting, and neutralising scanned text.

use std::net::IpAddr;
use std::time::Duration;

use rmap_core::{PortResult, Protocol, VulnSeverity, Vulnerability};
use rmap_log::Timestamp;

use crate::model::{HostReport, ScanReport};

/// Note shown wherever findings are listed: matching is by version only.
pub const FINDINGS_NOTE: &str = "Potential findings: CVEs are matched on the detected product \
    version only, so backported fixes and configuration are not taken into account. Verify \
    each finding before acting on it.";

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
}

/// Every finding in the report, worst first, then by score, host and port.
pub fn findings(r: &ScanReport) -> Vec<Finding<'_>> {
    let mut out: Vec<Finding> = r
        .hosts
        .iter()
        .flat_map(|h| {
            h.ports.iter().flat_map(move |p| {
                p.vulnerabilities.iter().map(move |v| Finding {
                    ip: h.ip,
                    port: p.port,
                    protocol: p.protocol,
                    vuln: v,
                })
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.vuln
            .severity
            .cmp(&a.vuln.severity)
            .then(
                b.vuln
                    .score
                    .unwrap_or(0.0)
                    .total_cmp(&a.vuln.score.unwrap_or(0.0)),
            )
            .then(a.ip.cmp(&b.ip))
            .then(a.port.cmp(&b.port))
            .then(a.vuln.id.cmp(&b.vuln.id))
    });
    out
}

/// Findings per severity, in [`SEVERITIES`] order.
pub fn severity_counts(r: &ScanReport) -> [usize; 4] {
    let mut counts = [0; 4];
    for f in findings(r) {
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

pub fn worst(p: &PortResult) -> Option<VulnSeverity> {
    p.vulnerabilities.iter().map(|v| v.severity).max()
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

pub fn service_name(p: &PortResult) -> &str {
    p.service.as_ref().map_or("", |s| s.name.as_str())
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
        }
    }

    /// The JSON sample with findings on its SSH port.
    pub(crate) fn fixture() -> ScanReport {
        let mut r = sample();
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
        r
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
