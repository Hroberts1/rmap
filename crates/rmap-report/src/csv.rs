//! CSV export: one row per open (or open|filtered) port, for spreadsheets.

use crate::model::ScanReport;
use crate::summary::{kev_note, neutralise, worst};

const HEADER: [&str; 14] = [
    "ip",
    "hostname",
    "port",
    "protocol",
    "state",
    "service",
    "product",
    "version",
    "info",
    "cves",
    "worst_severity",
    "cve_check",
    "exploited",
    "exposure_findings",
];

/// One RFC 4180 field. Every field is quoted, and one that a spreadsheet
/// would read as a formula gets a leading `'`, since banners and hostnames
/// come from the scanned devices. Controls other than line breaks and tabs
/// become U+FFFD so the file is safe to `cat`.
pub fn field(s: &str) -> String {
    let mut s = neutralise(s, &['\n', '\r', '\t']);
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        s.insert(0, '\'');
    }
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn row(out: &mut String, cells: &[&str]) {
    let fields: Vec<String> = cells.iter().map(|c| field(c)).collect();
    out.push_str(&fields.join(","));
    out.push_str("\r\n");
}

/// The report as CSV with a header row and CRLF line endings.
pub fn to_string(r: &ScanReport) -> String {
    let mut out = String::new();
    row(&mut out, &HEADER);
    let exposures = crate::exposure::findings(r);
    for h in r.hosts.iter().filter(|h| h.is_up()) {
        for (i, p) in h.ports.iter().enumerate() {
            // `high: Telnet (plaintext remote login); ...`. Host-wide
            // findings go on the host's first row only, so they count once.
            let exposure: Vec<String> = exposures
                .iter()
                .filter(|f| f.ip == h.ip)
                .filter(|f| match f.port {
                    Some(port) => port == p.port && f.protocol == Some(p.protocol),
                    None => i == 0,
                })
                .map(|f| format!("{}: {}", f.severity.as_str(), f.title))
                .collect();
            let s = p.service.as_ref();
            let cves: Vec<&str> = p.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
            // `CVE-2024-6387 actively exploited (CISA KEV, added 2024-07-01); ...`
            let exploited: Vec<String> = p
                .vulnerabilities
                .iter()
                .filter_map(|v| kev_note(v).map(|n| format!("{} {n}", v.id)))
                .collect();
            row(
                &mut out,
                &[
                    &h.ip.to_string(),
                    h.hostname.as_deref().unwrap_or(""),
                    &p.port.to_string(),
                    p.protocol.as_str(),
                    p.state.as_str(),
                    s.map_or("", |s| &s.name),
                    s.and_then(|s| s.product.as_deref()).unwrap_or(""),
                    s.and_then(|s| s.version.as_deref()).unwrap_or(""),
                    s.and_then(|s| s.info.as_deref()).unwrap_or(""),
                    &cves.join(" "),
                    worst(p).map_or("", |w| w.as_str()),
                    &p.vuln_check
                        .as_ref()
                        .map_or(String::new(), |c| c.to_string()),
                    &exploited.join("; "),
                    &exposure.join("; "),
                ],
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::tests::{fixture, hostile};

    #[test]
    fn quotes_per_rfc_4180() {
        assert_eq!(field("plain"), "\"plain\"");
        assert_eq!(field(""), "\"\"");
        assert_eq!(field("a,b"), "\"a,b\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("line1\r\nline2"), "\"line1\r\nline2\"");
    }

    #[test]
    fn neutralises_formulas_and_escapes() {
        for bad in ["=1+1", "+1", "-2+3", "@SUM(A1)", "\tx", "\rx"] {
            let f = field(bad);
            assert!(f.starts_with("\"'"), "{bad:?} -> {f:?}");
        }
        assert_eq!(field("a=1"), "\"a=1\"");
        assert_eq!(field("\x1b[31mred\x07"), "\"\u{FFFD}[31mred\u{FFFD}\"");
    }

    #[test]
    fn hostile_strings_are_inert() {
        let csv = to_string(&hostile());
        assert!(!csv.contains('\x1b') && !csv.contains('\x07') && !csv.contains('\u{202E}'));
        let rows = parse(&csv);
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(row.len(), HEADER.len(), "{row:?}");
            for cell in row {
                assert!(
                    !cell.starts_with(['=', '+', '-', '@', '\t', '\r']),
                    "{cell:?}"
                );
            }
        }
        assert!(rows[1][1].starts_with("'=cmd"));
        assert_eq!(rows[1][7], "'@SUM(1+1)");
    }

    #[test]
    fn exposure_findings_column() {
        let mut r = fixture();
        r.hosts.push(crate::exposure::tests::printer());
        let rows = parse(&to_string(&r));
        let last = HEADER.len() - 1;
        let telnet = rows
            .iter()
            .find(|r| r[0] == "10.9.0.26" && r[2] == "23")
            .unwrap();
        assert_eq!(telnet[last], "high: Telnet (plaintext remote login)");
        let raw = rows.iter().find(|r| r[2] == "9100").unwrap();
        assert_eq!(raw[last], "");
    }

    #[test]
    fn snapshot() {
        let csv = to_string(&fixture());
        assert!(csv.ends_with("\r\n") && !csv.replace("\r\n", "").contains('\n'));
        crate::summary::tests::snapshot("sample.csv", &csv);
    }

    /// Minimal RFC 4180 reader, to check the output parses back.
    fn parse(s: &str) -> Vec<Vec<String>> {
        let (mut rows, mut row, mut cell) = (Vec::new(), Vec::new(), String::new());
        let mut chars = s.chars().peekable();
        let mut quoted = false;
        while let Some(c) = chars.next() {
            match (quoted, c) {
                (true, '"') if chars.peek() == Some(&'"') => {
                    chars.next();
                    cell.push('"');
                }
                (_, '"') => quoted = !quoted,
                (false, ',') => row.push(std::mem::take(&mut cell)),
                (false, '\r') => {}
                (false, '\n') => {
                    row.push(std::mem::take(&mut cell));
                    rows.push(std::mem::take(&mut row));
                }
                (_, c) => cell.push(c),
            }
        }
        rows
    }
}
