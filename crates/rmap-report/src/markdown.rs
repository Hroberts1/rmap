//! Markdown export: a readable summary for pasting into a ticket.

use std::fmt::Write as _;

use rmap_core::{VulnTier, Vulnerability};

use crate::model::ScanReport;
use crate::summary::{
    FINDINGS_NOTE, Group, coverage_line, findings, groups, host_label, kev_note, no_findings_text,
    not_counted_line, one_line, service_name, severity_line, utc, version_text, vuln_data_line,
    worst,
};

/// Scanned text made safe for a Markdown table cell or list item: one
/// line, no controls, and every character Markdown (or HTML inside it)
/// could act on backslash-escaped.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in one_line(s).chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '&' | '~' | '#'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// ` · **actively exploited (CISA KEV, added …)**`, or nothing.
fn kev(v: &Vulnerability) -> String {
    kev_note(v).map_or(String::new(), |n| format!(" · **{}**", escape(&n)))
}

/// A group's upstream-only, conditional and client-only matches, one
/// collapsed line each: `Label: CVE-1 (high), CVE-2 (low).`
fn folded(g: &Group) -> Vec<String> {
    let upstream = g
        .distro
        .map(|d| format!("Upstream version; {} may have backported fixes", escape(d)));
    [
        (VulnTier::UpstreamOnly, upstream),
        (
            VulnTier::Conditional,
            Some("Conditional, platform not verified".into()),
        ),
        (
            VulnTier::ClientOnly,
            Some("Client-only, not counted on a listening port".into()),
        ),
    ]
    .into_iter()
    .filter_map(|(tier, label)| {
        let list = g.unique(tier);
        if list.is_empty() {
            return None;
        }
        let ids: Vec<String> = list
            .iter()
            .map(|f| {
                let only = f
                    .vuln
                    .condition
                    .as_ref()
                    .map_or(String::new(), |c| format!(", only with {}", escape(c)));
                format!(
                    "{} ({}{only})",
                    escape(&f.vuln.id),
                    f.vuln.severity.as_str()
                )
            })
            .collect();
        Some(format!(
            "{}: {}.",
            label.unwrap_or_else(|| "Upstream version".into()),
            ids.join(", ")
        ))
    })
    .collect()
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// The report as a Markdown document.
pub fn to_string(r: &ScanReport) -> String {
    let c = &r.config;
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(o, "# rmap scan report\n");
    let _ = writeln!(o, "> {FINDINGS_NOTE}\n");
    let _ = writeln!(o, "## Summary\n");
    let _ = writeln!(o, "- **Targets:** {}", escape(&c.targets));
    let _ = writeln!(
        o,
        "- **Ports:** {} ({} ports)",
        escape(&c.ports),
        c.port_count
    );
    let _ = writeln!(
        o,
        "- **Scan:** {}, timing {} (T{}), host discovery {}, service detection {}",
        c.scan_type.label(),
        escape(&c.timing_name),
        c.timing_level,
        on_off(c.discovery),
        on_off(c.service_detection)
    );
    let _ = writeln!(o, "- **Started:** {}", utc(r.started_ms));
    let finished = r.finished_ms.map_or("not finished".into(), utc);
    let _ = writeln!(o, "- **Finished:** {finished}");
    let _ = writeln!(
        o,
        "- **Duration:** {}",
        crate::summary::duration(r.elapsed())
    );
    let status = if r.status.is_complete() {
        r.status.as_str().to_string()
    } else {
        format!("{} (partial results)", r.status.as_str())
    };
    let _ = writeln!(o, "- **Status:** {status}");
    let _ = writeln!(o, "- **Hosts up:** {} of {}", r.hosts_up(), r.hosts.len());
    let _ = writeln!(o, "- **Open ports:** {}", r.open_ports());
    let _ = writeln!(o, "- **Potential CVEs:** {}", severity_line(r));
    if let Some(line) = not_counted_line(r) {
        let _ = writeln!(o, "- **Not counted:** {line}");
    }
    if let Some(line) = coverage_line(r) {
        let _ = writeln!(o, "- **CVE coverage:** {line}");
    }
    if let Some(line) = vuln_data_line(r) {
        let _ = writeln!(o, "- **Vulnerability data:** {}", escape(&line));
    }
    let _ = writeln!(o, "- **rmap version:** {}\n", escape(&r.rmap_version));

    let all = findings(r);
    let _ = writeln!(o, "## Hosts\n");
    let up: Vec<_> = r.hosts.iter().filter(|h| h.is_up()).collect();
    if up.is_empty() {
        let _ = writeln!(o, "No hosts up.\n");
    }
    for h in up {
        let _ = writeln!(o, "### {}\n", escape(&host_label(h)));
        if h.ports.is_empty() {
            let _ = writeln!(o, "No open ports found.\n");
            continue;
        }
        let _ = writeln!(o, "| Port | State | Service | Version | CVE check |");
        let _ = writeln!(o, "|---|---|---|---|---|");
        for p in &h.ports {
            let check = p.vuln_check.as_ref().map(|c| escape(&c.to_string()));
            let cves = match (check, worst(p)) {
                (Some(c), Some(s)) => format!("{c}, worst: {}", s.as_str()),
                (Some(c), None) => c,
                (None, Some(s)) => format!("{} (worst: {})", p.vulnerabilities.len(), s.as_str()),
                (None, None) => String::new(),
            };
            let _ = writeln!(
                o,
                "| {}/{} | {} | {} | {} | {cves} |",
                p.port,
                p.protocol.as_str(),
                escape(p.state.as_str()),
                escape(&service_name(p)),
                escape(&version_text(p)),
            );
        }
        let _ = writeln!(o);
        // Upstream-only, conditional and client-only matches are listed by
        // product below.
        let mine: Vec<_> = all
            .iter()
            .filter(|f| f.ip == h.ip && f.tier == VulnTier::Potential)
            .collect();
        if !mine.is_empty() {
            let _ = writeln!(o, "Potential findings:\n");
            for f in mine {
                let score = f.vuln.score.map_or(String::new(), |s| format!(", {s:.1}"));
                let _ = writeln!(
                    o,
                    "- **{}** ({}{score}) on {}/{}: {}{}",
                    escape(&f.vuln.id),
                    f.vuln.severity.as_str(),
                    f.port,
                    f.protocol.as_str(),
                    escape(&f.vuln.summary),
                    kev(f.vuln)
                );
            }
            let _ = writeln!(o);
        }
    }

    let _ = writeln!(o, "## Potential findings by product\n");
    let groups = groups(r);
    if groups.is_empty() {
        let _ = writeln!(o, "{}", no_findings_text(r));
    }
    for g in &groups {
        let _ = writeln!(o, "### {}\n", escape(&g.line()));
        for f in g.findings.iter().filter(|f| f.tier == VulnTier::Potential) {
            let score = f.vuln.score.map_or(String::new(), |s| format!(", {s:.1}"));
            let _ = writeln!(
                o,
                "- **{}** ({}{score}) on {} {}/{}: {}{}",
                escape(&f.vuln.id),
                f.vuln.severity.as_str(),
                f.ip,
                f.port,
                f.protocol.as_str(),
                escape(&f.vuln.summary),
                kev(f.vuln)
            );
        }
        for line in folded(g) {
            let _ = writeln!(o, "\n{line}");
        }
        let _ = writeln!(o);
    }
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::tests::{fixture, hostile};

    #[test]
    fn escapes_table_breakers_and_markup() {
        assert_eq!(escape("a|b"), "a\\|b");
        assert_eq!(escape("open|filtered"), "open\\|filtered");
        assert_eq!(escape("<b>x</b>"), "\\<b\\>x\\</b\\>");
        assert_eq!(
            escape("[x](http://e) *y* `z`"),
            "\\[x\\](http://e) \\*y\\* \\`z\\`"
        );
        assert_eq!(escape("a\nb\r\tc"), "a b  c");
        assert_eq!(escape("\\|"), "\\\\\\|");
        assert_eq!(escape("\x1b[2J"), "\u{FFFD}\\[2J");
    }

    #[test]
    fn hostile_strings_are_inert() {
        let md = to_string(&hostile());
        // Every `<` is backslash-escaped, so no raw HTML reaches a renderer.
        assert!(
            md.match_indices('<').all(|(i, _)| md[..i].ends_with('\\')),
            "{md}"
        );
        assert!(md.contains("\\<script\\>alert(1)\\</script\\>"));
        assert!(!md.chars().any(|c| c.is_control() && c != '\n'), "{md:?}");
        assert!(!md.contains('\u{202E}'));
        // Every table row still has exactly six unescaped pipes.
        for line in md.lines().filter(|l| l.starts_with("| ")) {
            let pipes = line.match_indices('|').filter(|(i, _)| {
                // A pipe is escaped when an odd number of backslashes precede it.
                line[..*i].chars().rev().take_while(|c| *c == '\\').count() % 2 == 0
            });
            assert_eq!(pipes.count(), 6, "{line}");
        }
    }

    #[test]
    fn empty_report() {
        let r = ScanReport::new(crate::builder::tests::config(), 0);
        let md = to_string(&r);
        assert!(md.contains("No hosts up."));
        assert!(md.contains("- **Potential CVEs:** none"));
        assert!(md.contains("No potential CVEs matched"));
        assert!(md.contains("not finished"));
    }

    #[test]
    fn snapshot() {
        crate::summary::tests::snapshot("sample.md", &to_string(&fixture()));
    }
}
