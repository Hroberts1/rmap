//! Nmap-compatible XML export.
//!
//! Emits the commonly consumed subset of Nmap's publicly documented XML
//! output format (`nmaprun`, `scaninfo`, `host`, `status`, `address`,
//! `hostnames`, `ports`, `extraports`, `port`, `state`, `service`, `cpe`,
//! `times`, `runstats`), so tools that import Nmap results can read rmap
//! scans. Written from the format's documentation with our own writer; no
//! Nmap code or DTD is used.

use std::fmt::Write as _;

use rmap_core::{DetectMethod, HostState, PortState, ScanType};
use rmap_log::Timestamp;

use crate::model::{HostReport, RunStatus, ScanReport};

/// Version of Nmap's XML output format we follow.
const XML_OUTPUT_VERSION: &str = "1.05";

/// A minimal streaming XML writer with correct escaping and indentation.
#[derive(Default)]
pub struct XmlWriter {
    out: String,
    stack: Vec<&'static str>,
}

impl XmlWriter {
    pub fn new() -> Self {
        Self::default()
    }

    fn indent(&mut self) {
        for _ in 0..self.stack.len() {
            self.out.push_str("  ");
        }
    }

    fn open_tag(&mut self, name: &str, attrs: &[(&str, &str)]) {
        self.indent();
        self.out.push('<');
        self.out.push_str(name);
        for (k, v) in attrs {
            let _ = write!(self.out, " {k}=\"{}\"", escape_attr(v));
        }
    }

    /// `<name attrs>` with children to follow.
    pub fn start(&mut self, name: &'static str, attrs: &[(&str, &str)]) {
        self.open_tag(name, attrs);
        self.out.push_str(">\n");
        self.stack.push(name);
    }

    /// `<name attrs/>`.
    pub fn empty(&mut self, name: &str, attrs: &[(&str, &str)]) {
        self.open_tag(name, attrs);
        self.out.push_str("/>\n");
    }

    /// `<name attrs>text</name>`.
    pub fn text(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) {
        self.open_tag(name, attrs);
        let _ = writeln!(self.out, ">{}</{name}>", escape_text(text));
    }

    /// Close the most recently started element.
    pub fn end(&mut self) {
        if let Some(name) = self.stack.pop() {
            self.indent();
            let _ = writeln!(self.out, "</{name}>");
        }
    }

    /// Close everything still open and return the document.
    pub fn finish(mut self) -> String {
        while !self.stack.is_empty() {
            self.end();
        }
        self.out
    }

    pub fn raw(&mut self, s: &str) {
        self.out.push_str(s);
    }
}

/// Characters XML 1.0 forbids outright become U+FFFD.
fn allowed(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

/// Escape character data.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if allowed(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

/// Escape an attribute value for double quotes. Whitespace other than space
/// is written as a character reference so parsers don't normalize it away.
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c if allowed(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

/// Convert a CPE 2.3 formatted string to the CPE 2.2 URI form Nmap XML uses
/// (`cpe:/a:vendor:product:version`). Anything else passes through.
pub fn cpe_uri(cpe: &str) -> String {
    let Some(rest) = cpe.strip_prefix("cpe:2.3:") else {
        return cpe.to_string();
    };
    // Split on unescaped colons.
    let mut fields = vec![String::new()];
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    let f = fields.last_mut().expect("never empty");
                    if next.is_ascii_alphanumeric() || matches!(next, '.' | '-' | '_') {
                        f.push(next);
                    } else {
                        let mut buf = [0; 4];
                        for b in next.encode_utf8(&mut buf).bytes() {
                            let _ = write!(f, "%{b:02x}");
                        }
                    }
                }
            }
            ':' => fields.push(String::new()),
            c => fields.last_mut().expect("never empty").push(c),
        }
    }
    // part, vendor, product, version, update, edition, language
    fields.truncate(7);
    for f in &mut fields {
        if f == "*" {
            f.clear();
        }
    }
    while fields.last().is_some_and(String::is_empty) {
        fields.pop();
    }
    format!("cpe:/{}", fields.join(":"))
}

fn scan_type_name(t: ScanType) -> &'static str {
    match t {
        ScanType::Connect => "connect",
        ScanType::Syn => "syn",
        ScanType::Udp => "udp",
    }
}

fn port_reason(state: PortState) -> &'static str {
    match state {
        PortState::Open => "syn-ack",
        PortState::Closed => "conn-refused",
        PortState::Filtered | PortState::OpenFiltered => "no-response",
    }
}

fn timestr(ms: i64) -> String {
    // Nmap uses ctime()-style local times; we write UTC so the output
    // doesn't depend on the machine's time zone.
    let t = Timestamp::from_unix_millis(ms);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// The report as an Nmap-compatible XML document.
pub fn to_string(r: &ScanReport) -> String {
    let start = (r.started_ms.div_euclid(1000)).to_string();
    let end_ms = r.finished_ms.unwrap_or(r.started_ms);
    let end = end_ms.div_euclid(1000).to_string();
    let c = &r.config;
    let mut args = format!(
        "rmap targets={} ports={} scan={} timing=T{} discovery={} service_detection={}",
        c.targets,
        c.ports,
        scan_type_name(c.scan_type),
        c.timing_level,
        c.discovery,
        c.service_detection
    );
    if !c.exclude.is_empty() {
        args += &format!(" exclude={}", c.exclude);
    }
    if let Some(rate) = c.max_rate {
        args += &format!(" max_rate={rate}");
    }

    let mut w = XmlWriter::new();
    w.raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE nmaprun>\n");
    w.start(
        "nmaprun",
        &[
            ("scanner", "rmap"),
            ("args", &args),
            ("start", &start),
            ("startstr", &timestr(r.started_ms)),
            ("version", &r.rmap_version),
            ("xmloutputversion", XML_OUTPUT_VERSION),
        ],
    );
    w.empty(
        "scaninfo",
        &[
            ("type", scan_type_name(c.scan_type)),
            ("protocol", c.scan_type.protocol().as_str()),
            ("numservices", &c.port_count.to_string()),
            ("services", &c.ports),
        ],
    );
    w.empty("verbose", &[("level", "0")]);
    w.empty("debugging", &[("level", "0")]);

    for h in &r.hosts {
        write_host(&mut w, h, &start, &end);
    }

    let up = r.hosts_up();
    let down = r.hosts.len() - up;
    let elapsed = format!("{:.2}", r.elapsed().as_secs_f64());
    let summary = format!(
        "rmap done at {}; {} IP address{} ({up} host{} up) scanned in {elapsed} seconds",
        timestr(end_ms),
        r.hosts.len(),
        if r.hosts.len() == 1 { "" } else { "es" },
        if up == 1 { "" } else { "s" },
    );
    let (exit, errormsg) = match r.status {
        RunStatus::Completed => ("success", None),
        RunStatus::Running => ("error", Some("scan still running when exported")),
        RunStatus::Stopped => ("error", Some("scan stopped by user; results are partial")),
        RunStatus::Failed => ("error", Some("scan engine failed; results are partial")),
    };
    w.start("runstats", &[]);
    let finished_time = end_ms.div_euclid(1000).to_string();
    let finished_str = timestr(end_ms);
    let mut attrs = vec![
        ("time", finished_time.as_str()),
        ("timestr", finished_str.as_str()),
        ("elapsed", elapsed.as_str()),
        ("summary", summary.as_str()),
        ("exit", exit),
    ];
    if let Some(msg) = errormsg {
        attrs.push(("errormsg", msg));
    }
    w.empty("finished", &attrs);
    w.empty(
        "hosts",
        &[
            ("up", &up.to_string()),
            ("down", &down.to_string()),
            ("total", &r.hosts.len().to_string()),
        ],
    );
    w.end();
    w.finish()
}

fn write_host(w: &mut XmlWriter, h: &HostReport, start: &str, end: &str) {
    w.start("host", &[("starttime", start), ("endtime", end)]);
    let (state, reason) = match h.state {
        HostState::Up => ("up", "host-response"),
        HostState::Assumed => ("up", "user-set"),
        HostState::Down => ("down", "no-response"),
    };
    w.empty(
        "status",
        &[("state", state), ("reason", reason), ("reason_ttl", "0")],
    );
    let addrtype = if h.ip.is_ipv4() { "ipv4" } else { "ipv6" };
    w.empty(
        "address",
        &[("addr", &h.ip.to_string()), ("addrtype", addrtype)],
    );
    if let Some(mac) = h.mac {
        // Nmap writes MACs in upper case.
        let addr = mac.to_string().to_ascii_uppercase();
        let mut attrs = vec![("addr", addr.as_str()), ("addrtype", "mac")];
        if let Some(vendor) = &h.vendor {
            attrs.push(("vendor", vendor));
        }
        w.empty("address", &attrs);
    }
    match &h.hostname {
        Some(name) => {
            w.start("hostnames", &[]);
            w.empty("hostname", &[("name", name), ("type", "PTR")]);
            w.end();
        }
        None => w.empty("hostnames", &[]),
    }

    if h.is_up() && h.ports.is_empty() && h.closed == 0 && h.filtered == 0 {
        w.empty("ports", &[]);
    } else if h.is_up() {
        w.start("ports", &[]);
        for (state, count) in [("closed", h.closed), ("filtered", h.filtered)] {
            if count > 0 {
                let reason = if state == "closed" {
                    "conn-refused"
                } else {
                    "no-response"
                };
                let count = count.to_string();
                w.start("extraports", &[("state", state), ("count", &count)]);
                w.empty("extrareasons", &[("reason", reason), ("count", &count)]);
                w.end();
            }
        }
        for p in &h.ports {
            let portid = p.port.to_string();
            w.start(
                "port",
                &[("protocol", p.protocol.as_str()), ("portid", &portid)],
            );
            w.empty(
                "state",
                &[
                    ("state", p.state.as_str()),
                    ("reason", port_reason(p.state)),
                    ("reason_ttl", "0"),
                ],
            );
            match &p.service {
                Some(s) => {
                    let conf = s.confidence.min(10).to_string();
                    let mut attrs: Vec<(&str, &str)> = vec![("name", &s.name)];
                    for (key, value) in [
                        ("product", &s.product),
                        ("version", &s.version),
                        ("extrainfo", &s.info),
                        ("ostype", &s.os_hint),
                    ] {
                        if let Some(v) = value {
                            attrs.push((key, v));
                        }
                    }
                    let method = match s.method {
                        DetectMethod::PortTable => "table",
                        DetectMethod::Banner | DetectMethod::Probe => "probed",
                    };
                    attrs.push(("method", method));
                    attrs.push(("conf", &conf));
                    if s.cpes.is_empty() {
                        w.empty("service", &attrs);
                    } else {
                        w.start("service", &attrs);
                        for cpe in &s.cpes {
                            w.text("cpe", &[], &cpe_uri(cpe));
                        }
                        w.end();
                    }
                }
                None => {
                    if let Some(name) = rmap_core::service_name(p.port) {
                        w.empty(
                            "service",
                            &[("name", name), ("method", "table"), ("conf", "3")],
                        );
                    }
                }
            }
            w.end();
        }
        w.end();
    }

    if let Some(rtt) = h.rtt {
        let us = rtt.as_micros().to_string();
        w.empty("times", &[("srtt", &us), ("rttvar", &us), ("to", "100000")]);
    }
    w.end();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::tests::sample;

    #[test]
    fn escapes_text_and_attributes() {
        assert_eq!(escape_text("a<b>&c\"'"), "a&lt;b&gt;&amp;c\"'");
        assert_eq!(
            escape_attr("<\"it's\" & more>"),
            "&lt;&quot;it&apos;s&quot; &amp; more&gt;"
        );
        assert_eq!(escape_attr("a\tb\nc\rd"), "a&#9;b&#10;c&#13;d");
        assert_eq!(escape_text("bell\u{7}nul\0"), "bell\u{FFFD}nul\u{FFFD}");
        assert_eq!(escape_text("\u{FFFE}é漢😀"), "\u{FFFD}é漢😀");
        assert_eq!(escape_text(""), "");
    }

    #[test]
    fn writer_nests_and_closes() {
        let mut w = XmlWriter::new();
        w.start("a", &[("x", "1&2")]);
        w.text("b", &[], "<hi>");
        w.empty("c", &[]);
        let out = w.finish();
        assert_eq!(
            out,
            "<a x=\"1&amp;2\">\n  <b>&lt;hi&gt;</b>\n  <c/>\n</a>\n"
        );
    }

    #[test]
    fn cpe_conversion() {
        assert_eq!(
            cpe_uri("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"),
            "cpe:/a:openbsd:openssh:9.6p1"
        );
        assert_eq!(
            cpe_uri("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"),
            "cpe:/o:linux:linux_kernel"
        );
        assert_eq!(
            cpe_uri("cpe:2.3:a:microsoft:internet_information_services:10\\.0:*:*:*:*:*:*:*"),
            "cpe:/a:microsoft:internet_information_services:10.0"
        );
        assert_eq!(cpe_uri("cpe:2.3:a:x:y\\:z:1"), "cpe:/a:x:y%3az:1");
        assert_eq!(cpe_uri("cpe:2.3:a:x:y:*:sp1"), "cpe:/a:x:y::sp1");
        assert_eq!(
            cpe_uri("cpe:/a:apache:http_server"),
            "cpe:/a:apache:http_server"
        );
        assert_eq!(cpe_uri("cpe:2.3:"), "cpe:/");
        assert_eq!(cpe_uri("cpe:2.3:a:x\\"), "cpe:/a:x");
    }

    #[test]
    fn hostile_strings_stay_well_formed() {
        let mut r = sample();
        r.config.targets = "\"><script>&".into();
        r.config.exclude = "<plc>&".into();
        r.config.max_rate = Some(10);
        r.hosts[0].hostname = Some("evil\"<host>&'\n".into());
        let s = r.hosts[0].ports[0].service.as_mut().unwrap();
        s.product = Some("Open<SSH>".into());
        s.cpes = vec!["cpe:/a:<x>".into()];
        let xml = to_string(&r);
        assert!(
            xml.contains("targets=&quot;&gt;&lt;script&gt;&amp;"),
            "{xml}"
        );
        assert!(
            xml.contains("exclude=&lt;plc&gt;&amp; max_rate=10"),
            "{xml}"
        );
        assert!(xml.contains("name=\"evil&quot;&lt;host&gt;&amp;&apos;&#10;\""));
        assert!(xml.contains("product=\"Open&lt;SSH&gt;\""));
        assert!(xml.contains("<cpe>cpe:/a:&lt;x&gt;</cpe>"));
        assert_balanced(&xml);
    }

    /// Cheap well-formedness check: every open tag is closed in order, and
    /// no raw `<` or `&` appears outside markup.
    fn assert_balanced(xml: &str) {
        let mut stack = Vec::new();
        let body = xml.split_once("<!DOCTYPE nmaprun>\n").unwrap().1;
        let mut rest = body;
        while let Some(i) = rest.find('<') {
            let text = &rest[..i];
            assert!(!text.contains('>'), "stray > in {text:?}");
            for (j, _) in text.match_indices('&') {
                let ent = &text[j..];
                assert!(
                    ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;", "&#"]
                        .iter()
                        .any(|e| ent.starts_with(e)),
                    "bad entity in {text:?}"
                );
            }
            let close = rest[i..].find('>').unwrap() + i;
            let tag = &rest[i + 1..close];
            assert!(!tag.contains('<'), "nested < in tag {tag:?}");
            if let Some(name) = tag.strip_prefix('/') {
                assert_eq!(stack.pop(), Some(name.to_string()));
            } else if !tag.ends_with('/') {
                stack.push(tag.split(' ').next().unwrap().to_string());
            }
            rest = &rest[close + 1..];
        }
        assert!(stack.is_empty(), "unclosed: {stack:?}");
    }

    #[test]
    fn snapshot() {
        let xml = to_string(&sample());
        assert_balanced(&xml);
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.xml");
        // After an intended format change, regenerate with
        // `RMAP_UPDATE_SNAPSHOTS=1 cargo test -p rmap-report` and review the diff.
        if std::env::var_os("RMAP_UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(path, &xml).unwrap();
        }
        let expected = std::fs::read_to_string(path).unwrap();
        assert_eq!(xml, expected.replace("\r\n", "\n"));
    }

    #[test]
    fn mac_address_and_vendor() {
        let mut r = sample();
        r.hosts[0].mac = Some("00:11:32:aa:bb:cc".parse().unwrap());
        r.hosts[0].vendor = Some("Synology".into());
        r.hosts[1].mac = Some("da:00:00:00:00:01".parse().unwrap());
        let xml = to_string(&r);
        assert!(
            xml.contains(concat!(
                "<address addr=\"10.0.0.2\" addrtype=\"ipv4\"/>\n",
                "    <address addr=\"00:11:32:AA:BB:CC\" addrtype=\"mac\" vendor=\"Synology\"/>"
            )),
            "{xml}"
        );
        assert!(xml.contains("<address addr=\"DA:00:00:00:00:01\" addrtype=\"mac\"/>"));
        assert_balanced(&xml);
    }

    #[test]
    fn partial_scans_report_an_error_exit() {
        let mut r = sample();
        r.status = RunStatus::Stopped;
        let xml = to_string(&r);
        assert!(xml.contains("exit=\"error\" errormsg=\"scan stopped by user"));
        assert_balanced(&xml);
        let empty = ScanReport::new(crate::builder::tests::config(), 0);
        let xml = to_string(&empty);
        assert!(xml.contains("<hosts up=\"0\" down=\"0\" total=\"0\"/>"));
        assert_balanced(&xml);
    }
}
