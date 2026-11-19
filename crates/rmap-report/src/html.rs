//! HTML export: one self-contained, printable page to hand to a client.
//! Inline CSS only: no JavaScript, fonts or other requests, and a CSP that
//! blocks them even if something slipped through.

use std::fmt::Write as _;

use crate::model::{HostReport, ScanReport};
use crate::summary::{
    FINDINGS_NOTE, SEVERITIES, duration, findings, kev_note, no_findings_text, one_line,
    service_name, severity_counts, unchecked_counts, utc, version_text, vuln_data_line, worst,
};

const STYLE: &str = r#"
:root { color-scheme: light dark; --bg: #fff; --fg: #1d2330; --muted: #5d6675; --line: #d9dde4;
  --panel: #f5f6f8; --note: #fff7e0; --note-line: #e0b84d;
  --critical: #b3261e; --high: #c25400; --medium: #8a6d00; --low: #476282; }
@media screen and (prefers-color-scheme: dark) {
  :root { --bg: #15181e; --fg: #e3e6eb; --muted: #9aa3b1; --line: #343a45; --panel: #1e222a;
    --note: #2e2914; --note-line: #8a7224;
    --critical: #ff8a80; --high: #ffab66; --medium: #e8c860; --low: #9db8d9; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 32px 16px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 32px 0 12px; padding-bottom: 4px; border-bottom: 1px solid var(--line); }
h3 { font-size: 16px; margin: 0 0 8px; }
.muted { color: var(--muted); }
.note { background: var(--note); border-left: 4px solid var(--note-line); padding: 8px 12px; margin: 16px 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 12px; }
.tile b { display: block; font-size: 24px; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
th { font-size: 13px; color: var(--muted); font-weight: 600; }
.kv th { width: 160px; }
.host { margin: 0 0 24px; break-inside: avoid; }
.sev { font-weight: 700; text-transform: uppercase; font-size: 12px; letter-spacing: .03em; }
.critical { color: var(--critical); } .high { color: var(--high); }
.medium { color: var(--medium); } .low { color: var(--low); }
.kev { font-weight: 700; color: var(--critical); } .unchecked { color: var(--medium); }
footer { margin-top: 40px; font-size: 13px; color: var(--muted); }
@media print { main { max-width: none; padding: 0; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
"#;

/// Scanned text made safe for HTML text or a quoted attribute.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in one_line(s).chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn tile(o: &mut String, value: &str, label: &str) {
    let _ = writeln!(
        o,
        "<div class=\"tile\"><b>{value}</b><span class=\"muted\">{label}</span></div>"
    );
}

fn write_host(o: &mut String, h: &HostReport) {
    let _ = write!(o, "<section class=\"host\">\n<h3>{}", h.ip);
    if let Some(name) = &h.hostname {
        let _ = write!(o, " <span class=\"muted\">{}</span>", escape(name));
    }
    let _ = writeln!(o, "</h3>");
    if h.ports.is_empty() {
        let _ = writeln!(o, "<p class=\"muted\">No open ports found.</p>\n</section>");
        return;
    }
    let _ = writeln!(
        o,
        "<table>\n<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>CVE check</th></tr></thead>\n<tbody>"
    );
    for p in &h.ports {
        // The check status, else the bare count (older reports).
        let lead = match &p.vuln_check {
            Some(c) if c.is_unchecked() => {
                format!(
                    "<span class=\"unchecked\">{}</span>",
                    escape(&c.to_string())
                )
            }
            Some(c) => escape(&c.to_string()),
            None if p.vulnerabilities.is_empty() => String::new(),
            None => p.vulnerabilities.len().to_string(),
        };
        let cves = match worst(p) {
            Some(s) => format!(
                "{lead} <span class=\"sev {s}\">worst {s}</span>",
                s = s.as_str()
            ),
            None => lead,
        };
        let _ = writeln!(
            o,
            "<tr><td>{}/{}</td><td>{}</td><td>{}</td><td>{}</td><td>{cves}</td></tr>",
            p.port,
            p.protocol.as_str(),
            p.state.as_str(),
            escape(&service_name(p)),
            escape(&version_text(p)),
        );
    }
    let _ = writeln!(o, "</tbody>\n</table>\n</section>");
}

/// The report as a standalone HTML page.
pub fn to_string(r: &ScanReport) -> String {
    let c = &r.config;
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(
        o,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n\
         <title>Network scan report: {}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>",
        escape(&c.targets)
    );
    let _ = writeln!(o, "<h1>Network scan report</h1>");
    let _ = writeln!(
        o,
        "<p class=\"muted\">{} · {}</p>",
        escape(&c.targets),
        utc(r.started_ms)
    );
    let _ = writeln!(o, "<p class=\"note\">{}</p>", escape(FINDINGS_NOTE));

    let _ = writeln!(o, "<h2>Summary</h2>\n<div class=\"tiles\">");
    let counts = severity_counts(r);
    tile(
        o,
        &format!("{} / {}", r.hosts_up(), r.hosts.len()),
        "hosts up",
    );
    tile(o, &r.open_ports().to_string(), "open ports");
    tile(
        o,
        &counts.iter().sum::<usize>().to_string(),
        "potential CVEs",
    );
    for (sev, n) in SEVERITIES.iter().zip(counts).filter(|(_, n)| *n > 0) {
        let label = format!("<span class=\"sev {0}\">{0}</span>", sev.as_str());
        tile(o, &n.to_string(), &label);
    }
    let _ = writeln!(o, "</div>");

    let on_off = |b: bool| if b { "on" } else { "off" };
    let status = if r.status.is_complete() {
        r.status.as_str().to_string()
    } else {
        format!("{} (partial results)", r.status.as_str())
    };
    let mut rows = vec![
        ("Targets", escape(&c.targets)),
        (
            "Ports",
            format!("{} ({} ports)", escape(&c.ports), c.port_count),
        ),
        (
            "Scan",
            format!(
                "{}, timing {} (T{}), host discovery {}, service detection {}",
                c.scan_type.label(),
                escape(&c.timing_name),
                c.timing_level,
                on_off(c.discovery),
                on_off(c.service_detection)
            ),
        ),
        ("Started", utc(r.started_ms)),
        ("Finished", r.finished_ms.map_or("not finished".into(), utc)),
        ("Duration", duration(r.elapsed())),
        ("Status", status),
        ("rmap version", escape(&r.rmap_version)),
    ];
    if let Some(line) = vuln_data_line(r) {
        rows.push(("Vulnerability data", escape(&line)));
    }
    if let (n, total @ 1..) = unchecked_counts(r) {
        rows.push(("Not checked for CVEs", format!("{n} of {total} ports")));
    }
    let _ = writeln!(o, "<table class=\"kv\">\n<tbody>");
    for (k, v) in rows {
        let _ = writeln!(o, "<tr><th>{k}</th><td>{v}</td></tr>");
    }
    let _ = writeln!(o, "</tbody>\n</table>");

    let _ = writeln!(o, "<h2>Hosts</h2>");
    let up: Vec<_> = r.hosts.iter().filter(|h| h.is_up()).collect();
    if up.is_empty() {
        let _ = writeln!(o, "<p class=\"muted\">No hosts up.</p>");
    }
    for h in up {
        write_host(o, h);
    }

    let _ = writeln!(o, "<h2>Potential findings</h2>");
    let all = findings(r);
    if all.is_empty() {
        let _ = writeln!(o, "<p class=\"muted\">{}</p>", escape(&no_findings_text(r)));
    } else {
        let _ = writeln!(
            o,
            "<table>\n<thead><tr><th>Severity</th><th>CVE</th><th>Score</th><th>Host</th><th>Port</th><th>Summary</th></tr></thead>\n<tbody>"
        );
        for f in all {
            let sev = f.vuln.severity.as_str();
            let score = f.vuln.score.map_or(String::new(), |s| format!("{s:.1}"));
            let kev = kev_note(f.vuln).map_or(String::new(), |n| {
                format!(" <span class=\"kev\">{}</span>", escape(&n))
            });
            let _ = writeln!(
                o,
                "<tr><td><span class=\"sev {sev}\">{sev}</span></td><td>{}</td><td>{score}</td><td>{}</td><td>{}/{}</td><td>{}{kev}</td></tr>",
                escape(&f.vuln.id),
                f.ip,
                f.port,
                f.protocol.as_str(),
                escape(&f.vuln.summary)
            );
        }
        let _ = writeln!(o, "</tbody>\n</table>");
    }
    let _ = writeln!(
        o,
        "<footer>Generated by rmap {}. Times are UTC.</footer>\n</main>\n</body>\n</html>",
        escape(&r.rmap_version)
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::tests::{fixture, hostile};

    #[test]
    fn escapes_html_specials() {
        assert_eq!(
            escape("<a href=\"x\" title='y'>&amp;</a>"),
            "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;amp;&lt;/a&gt;"
        );
        assert_eq!(escape("a\x1b[1mb\u{202E}"), "a\u{FFFD}[1mb\u{FFFD}");
    }

    #[test]
    fn hostile_strings_are_inert() {
        let html = to_string(&hostile());
        assert_eq!(html.matches("<script").count(), 0, "{html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.chars().any(|c| c.is_control() && c != '\n'));
        assert!(!html.contains('\u{202E}'));
    }

    #[test]
    fn self_contained_and_printable() {
        let html = to_string(&fixture());
        for banned in [
            "<script", "<link", "<img", "@import", "url(", "http://", "https://",
        ] {
            assert!(!html.contains(banned), "{banned}");
        }
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("prefers-color-scheme: dark") && html.contains("@media print"));
        assert!(html.contains("Verify each finding before acting on it."));
    }

    #[test]
    fn snapshot() {
        crate::summary::tests::snapshot("sample.html", &to_string(&fixture()));
    }
}
