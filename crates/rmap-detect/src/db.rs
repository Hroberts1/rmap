//! The probe database: what to send to a port and how to read the answer.
//!
//! The database is a text file in an rmap-specific format, embedded in the
//! binary (`probes.txt`) and parsed once at startup. Each `probe` block says
//! what to send and when; each `match` line that follows belongs to that
//! probe and says how to recognise a response.
//!
//! ```text
//! # Comments start with `#`. Indentation is for readability only.
//! probe http-get
//!   send     "GET / HTTP/1.0\r\n\r\n"   # quoted, with \r \n \t \0 \\ \" \xHH
//!   ports    80,8000-8100                # where this probe is tried first
//!   wait     5s                          # how long to read (ms or s)
//!   generic                              # also try it on unknown ports
//!   fallback banner                      # also try these probes' rules
//!
//! match http ^HTTP/1\.[01] \d\d\d[\s\S]*?\r\nServer: nginx(?:/([\d.]+))?
//!   product  nginx
//!   version  $1
//!   info     $2
//!   os       Linux
//!   confidence 9
//! ```
//!
//! * `send` takes a quoted string, or `@name` for a payload built in code
//!   (see [`Builtin`]). A probe without `send` just waits for a banner.
//! * `protocol tcp|udp` defaults to `tcp`.
//! * A `match` line is `match <service> <pattern>`; the pattern is the rest
//!   of the line, in the syntax of [`crate::pattern`]. Leading and trailing
//!   spaces are trimmed, so write `\x20` for a space at either end.
//! * `product`, `version`, `info` and `os` are templates: `$1`–`$9` insert a
//!   capture group. A field that comes out empty is left unset.

use std::fmt;
use std::time::Duration;

use rmap_core::{PortList, Protocol, Service};

use crate::pattern::{Captures, Pattern};

/// The database shipped with rmap.
pub const BUILTIN: &str = include_str!("probes.txt");

/// Longest text a template expansion may produce.
const MAX_FIELD_LEN: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for DbError {}

/// Payloads too fiddly to write as a string, built in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    /// A TLS 1.2 ClientHello. Responses are analysed by [`crate::tls`]
    /// instead of match rules.
    TlsClientHello,
    /// SMB1 negotiate offering NT LM 0.12 and SMB 2.x dialects.
    SmbNegotiate,
    /// MongoDB `buildInfo` command in an OP_MSG.
    MongoBuildInfo,
    // UDP requests (see [`crate::udp`]). All but SSDP have binary replies,
    // decoded in code; match rules then read any text the decoder found.
    DnsVersionBind,
    MdnsServices,
    NtpReadvar,
    NtpClient,
    SnmpV2c,
    SnmpV1,
    NetbiosStatus,
    SsdpSearch,
}

impl Builtin {
    fn parse(name: &str) -> Option<Builtin> {
        Some(match name {
            "tls-client-hello" => Builtin::TlsClientHello,
            "smb-negotiate" => Builtin::SmbNegotiate,
            "mongodb-buildinfo" => Builtin::MongoBuildInfo,
            "dns-version-bind" => Builtin::DnsVersionBind,
            "mdns-services" => Builtin::MdnsServices,
            "ntp-readvar" => Builtin::NtpReadvar,
            "ntp-client" => Builtin::NtpClient,
            "snmp-v2c-get" => Builtin::SnmpV2c,
            "snmp-v1-get" => Builtin::SnmpV1,
            "netbios-status" => Builtin::NetbiosStatus,
            "ssdp-search" => Builtin::SsdpSearch,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Send nothing; wait for the service to speak first.
    None,
    Bytes(Vec<u8>),
    Builtin(Builtin),
}

/// A `product`/`version`/`info`/`os` value with `$N` placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template(String);

impl Template {
    fn parse(s: &str, groups: usize) -> Result<Template, String> {
        let b = s.as_bytes();
        for (i, &c) in b.iter().enumerate() {
            if c == b'$' {
                match b.get(i + 1) {
                    Some(d @ b'1'..=b'9') if usize::from(d - b'0') <= groups => {}
                    Some(d @ b'1'..=b'9') => {
                        return Err(format!(
                            "${} refers to a group the pattern doesn't have",
                            *d as char
                        ));
                    }
                    _ => return Err("`$` must be followed by a group number 1-9".into()),
                }
            }
        }
        Ok(Template(s.to_string()))
    }

    /// The template as written in the database.
    pub fn source(&self) -> &str {
        &self.0
    }

    /// Fill in capture groups. Captured bytes are decoded leniently and
    /// stripped of control characters; empty results become `None`.
    pub fn expand(&self, caps: &Captures, haystack: &[u8]) -> Option<String> {
        let mut out = String::new();
        let mut chars = self.0.chars();
        while let Some(c) = chars.next() {
            if c == '$' {
                if let Some(d) = chars.next().and_then(|d| d.to_digit(10))
                    && let Some(bytes) = caps.get(haystack, d as usize)
                {
                    out.push_str(&clean(bytes));
                }
            } else {
                out.push(c);
            }
        }
        // Separators left dangling by an empty optional group go too:
        // "protocol 2.0; $3" with no $3 becomes "protocol 2.0".
        let out = out.split_whitespace().collect::<Vec<_>>().join(" ");
        let out = out.trim_matches([';', ',', ' ']).to_string();
        if out.is_empty() {
            None
        } else {
            Some(truncate(out, MAX_FIELD_LEN))
        }
    }
}

/// Printable text from untrusted bytes.
fn clean(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn truncate(mut s: String, max: usize) -> String {
    if let Some((i, _)) = s.char_indices().nth(max) {
        s.truncate(i);
        s.push('…');
    }
    s
}

#[derive(Debug, Clone)]
pub struct Rule {
    /// Position in the whole database, for logs and test coverage.
    pub id: usize,
    /// Line in the database source.
    pub line: usize,
    pub service: String,
    pub pattern: Pattern,
    pub product: Option<Template>,
    pub version: Option<Template>,
    pub info: Option<Template>,
    pub os: Option<Template>,
    pub confidence: Option<u8>,
}

impl Rule {
    /// The service this rule describes, if it matches `response`.
    pub fn apply(&self, response: &[u8]) -> Option<Service> {
        let caps = self.pattern.captures(response)?;
        let field = |t: &Option<Template>| t.as_ref().and_then(|t| t.expand(&caps, response));
        let product = field(&self.product);
        let version = field(&self.version);
        let confidence = self.confidence.unwrap_or(match (&product, &version) {
            (Some(_), Some(_)) => 9,
            (Some(_), None) => 8,
            _ => 7,
        });
        Some(Service {
            name: self.service.clone(),
            product,
            version,
            info: field(&self.info),
            os_hint: field(&self.os),
            cpes: Vec::new(),
            method: rmap_core::DetectMethod::Probe,
            confidence,
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub name: String,
    pub protocol: Protocol,
    pub payload: Payload,
    /// Ports where this probe is tried before any other, sorted.
    pub ports: Vec<u16>,
    pub wait: Duration,
    /// Try this probe on ports no probe claims.
    pub generic: bool,
    /// Indices of probes whose rules also apply to this probe's responses.
    pub fallback: Vec<usize>,
    pub rules: Vec<Rule>,
    pub line: usize,
}

impl Probe {
    pub fn likely_on(&self, port: u16) -> bool {
        self.ports.binary_search(&port).is_ok()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Database {
    pub probes: Vec<Probe>,
}

/// A rule that matched, and what it says about the service.
#[derive(Debug, Clone)]
pub struct Matched<'a> {
    pub probe: &'a Probe,
    pub rule: &'a Rule,
    pub service: Service,
}

impl Database {
    pub fn parse(src: &str) -> Result<Database, DbError> {
        Builder::default().run(src)
    }

    pub fn probe(&self, name: &str) -> Option<usize> {
        self.probes.iter().position(|p| p.name == name)
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.probes.iter().flat_map(|p| &p.rules)
    }

    /// Match a response to probe `index` against its rules, then against
    /// its fallback probes' rules, first match wins.
    pub fn identify(&self, index: usize, response: &[u8]) -> Option<Matched<'_>> {
        let probe = self.probes.get(index)?;
        let order = std::iter::once(index).chain(probe.fallback.iter().copied());
        for i in order {
            let p = &self.probes[i];
            for rule in &p.rules {
                if let Some(service) = rule.apply(response) {
                    return Some(Matched {
                        probe: p,
                        rule,
                        service,
                    });
                }
            }
        }
        None
    }
}

#[derive(Default)]
struct Builder {
    db: Database,
    /// Fallback names, resolved once every probe is known.
    pending_fallbacks: Vec<(usize, usize, String)>,
    rules: usize,
}

impl Builder {
    fn run(mut self, src: &str) -> Result<Database, DbError> {
        for (n, raw) in src.lines().enumerate() {
            let line = n + 1;
            let text = raw.trim_start();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let (key, rest) = match text.split_once(char::is_whitespace) {
                Some((k, r)) => (k, r.trim()),
                None => (text.trim_end(), ""),
            };
            self.line(key, rest, line)
                .map_err(|message| DbError { line, message })?;
        }
        for (probe, line, name) in std::mem::take(&mut self.pending_fallbacks) {
            let Some(i) = self.db.probe(&name) else {
                return Err(DbError {
                    line,
                    message: format!("fallback to unknown probe `{name}`"),
                });
            };
            if i != probe && !self.db.probes[probe].fallback.contains(&i) {
                self.db.probes[probe].fallback.push(i);
            }
        }
        if self.db.probes.is_empty() {
            return Err(DbError {
                line: 0,
                message: "no probes defined".into(),
            });
        }
        Ok(self.db)
    }

    fn probe(&mut self) -> Result<&mut Probe, String> {
        self.db
            .probes
            .last_mut()
            .ok_or_else(|| "expected `probe <name>` first".to_string())
    }

    fn rule(&mut self) -> Result<&mut Rule, String> {
        self.probe()?
            .rules
            .last_mut()
            .ok_or_else(|| "expected `match <service> <pattern>` first".to_string())
    }

    fn line(&mut self, key: &str, rest: &str, line: usize) -> Result<(), String> {
        let need_value = |what: &str| -> Result<(), String> {
            if rest.is_empty() {
                Err(format!("`{key}` needs {what}"))
            } else {
                Ok(())
            }
        };
        match key {
            "probe" => {
                need_value("a name")?;
                if rest.contains(char::is_whitespace) {
                    return Err("probe names can't contain spaces".into());
                }
                if self.db.probe(rest).is_some() {
                    return Err(format!("probe `{rest}` is defined twice"));
                }
                self.db.probes.push(Probe {
                    name: rest.to_string(),
                    protocol: Protocol::Tcp,
                    payload: Payload::None,
                    ports: Vec::new(),
                    wait: Duration::from_secs(5),
                    generic: false,
                    fallback: Vec::new(),
                    rules: Vec::new(),
                    line,
                });
            }
            "protocol" => {
                let p = self.probe_settings()?;
                p.protocol = match rest {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    _ => return Err("protocol must be `tcp` or `udp`".into()),
                };
            }
            "send" => {
                need_value("a quoted string or @builtin")?;
                let payload = if let Some(name) = rest.strip_prefix('@') {
                    Payload::Builtin(
                        Builtin::parse(name).ok_or_else(|| format!("unknown builtin `@{name}`"))?,
                    )
                } else {
                    Payload::Bytes(unquote(rest)?)
                };
                let p = self.probe_settings()?;
                if p.payload != Payload::None {
                    return Err("probe already has a payload".into());
                }
                p.payload = payload;
            }
            "ports" => {
                need_value("a port list")?;
                let list = PortList::parse(rest).map_err(|e| e.to_string())?;
                let p = self.probe_settings()?;
                p.ports.extend_from_slice(list.as_slice());
                p.ports.sort_unstable();
                p.ports.dedup();
            }
            "wait" => {
                need_value("a duration")?;
                let ms = parse_duration_ms(rest)?;
                self.probe_settings()?.wait = Duration::from_millis(ms);
            }
            "generic" => {
                if !rest.is_empty() {
                    return Err("`generic` takes no value".into());
                }
                self.probe_settings()?.generic = true;
            }
            "fallback" => {
                need_value("probe names")?;
                self.probe_settings()?;
                let index = self.db.probes.len() - 1;
                for name in rest.split_whitespace() {
                    self.pending_fallbacks.push((index, line, name.to_string()));
                }
            }
            "match" => {
                let Some((service, pattern)) = rest.split_once(char::is_whitespace) else {
                    return Err("expected `match <service> <pattern>`".into());
                };
                let pattern = Pattern::new(pattern.trim()).map_err(|e| e.to_string())?;
                let id = self.rules;
                let probe = self.probe()?;
                probe.rules.push(Rule {
                    id,
                    line,
                    service: service.to_string(),
                    pattern,
                    product: None,
                    version: None,
                    info: None,
                    os: None,
                    confidence: None,
                });
                self.rules += 1;
            }
            "product" | "version" | "info" | "os" => {
                need_value("a value")?;
                let rule = self.rule()?;
                let template = Template::parse(rest, rule.pattern.groups())?;
                let slot = match key {
                    "product" => &mut rule.product,
                    "version" => &mut rule.version,
                    "info" => &mut rule.info,
                    _ => &mut rule.os,
                };
                if slot.is_some() {
                    return Err(format!("`{key}` given twice"));
                }
                *slot = Some(template);
            }
            "confidence" => {
                let n: u8 = rest
                    .parse()
                    .ok()
                    .filter(|n| *n <= 10)
                    .ok_or("confidence must be 0-10")?;
                self.rule()?.confidence = Some(n);
            }
            _ => return Err(format!("unknown keyword `{key}`")),
        }
        Ok(())
    }

    /// The current probe, for a setting that must come before its rules.
    fn probe_settings(&mut self) -> Result<&mut Probe, String> {
        let p = self.probe()?;
        if !p.rules.is_empty() {
            return Err("probe settings must come before its `match` lines".into());
        }
        Ok(p)
    }
}

fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let (num, scale) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1000)
    } else {
        return Err("duration needs a unit: `ms` or `s`".into());
    };
    match num.trim().parse::<u64>() {
        Ok(n) if n * scale <= 60_000 && n > 0 => Ok(n * scale),
        _ => Err("duration must be between 1ms and 60s".into()),
    }
}

/// Decode a double-quoted string with `\r \n \t \0 \\ \" \xHH` escapes.
fn unquote(s: &str) -> Result<Vec<u8>, String> {
    let inner = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .filter(|_| s.len() >= 2)
        .ok_or("payload must be a double-quoted string")?;
    let b = inner.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c == b'"' {
            return Err("unescaped `\"` inside payload".into());
        }
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let Some(&e) = b.get(i) else {
            return Err("payload ends with a backslash".into());
        };
        i += 1;
        out.push(match e {
            b'r' => b'\r',
            b'n' => b'\n',
            b't' => b'\t',
            b'0' => 0,
            b'\\' => b'\\',
            b'"' => b'"',
            b'x' => {
                let hex = b
                    .get(i..i + 2)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or("expected two hex digits after \\x")?;
                i += 2;
                hex
            }
            _ => return Err(format!("unknown escape `\\{}`", e as char)),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# a comment
probe banner
  wait 2s
match ssh ^SSH-([\d.]+)-OpenSSH_([\w.]+)
  product OpenSSH
  version $2
  info    protocol $1

probe web
  send  "GET / HTTP/1.0\r\n\r\n"
  ports 80, 8080-8081
  generic
  fallback banner
match http ^HTTP/1\.[01] \d+
  confidence 6
"#;

    #[test]
    fn parses_sample() {
        let db = Database::parse(SAMPLE).unwrap();
        assert_eq!(db.probes.len(), 2);
        let web = &db.probes[1];
        assert_eq!(
            web.payload,
            Payload::Bytes(b"GET / HTTP/1.0\r\n\r\n".to_vec())
        );
        assert_eq!(web.ports, vec![80, 8080, 8081]);
        assert!(web.generic && web.likely_on(8081) && !web.likely_on(22));
        assert_eq!(web.fallback, vec![0]);
        assert_eq!(db.probes[0].wait, Duration::from_secs(2));
        assert_eq!(web.wait, Duration::from_secs(5));

        // The web probe's response falls back to banner rules.
        let m = db.identify(1, b"SSH-2.0-OpenSSH_9.6p1\r\n").unwrap();
        assert_eq!(m.rule.line, 5);
        assert_eq!(m.service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(m.service.version.as_deref(), Some("9.6p1"));
        assert_eq!(m.service.info.as_deref(), Some("protocol 2.0"));
        assert_eq!(m.service.confidence, 9);
        let m = db.identify(1, b"HTTP/1.1 200 OK\r\n").unwrap();
        assert_eq!((m.service.name.as_str(), m.service.confidence), ("http", 6));
        assert!(db.identify(0, b"HTTP/1.1 200 OK\r\n").is_none());
        assert!(db.identify(9, b"x").is_none());
    }

    #[test]
    fn templates_clean_and_drop_empty_values() {
        let db = Database::parse(
            "probe p\nmatch x ^a(b*)c(.*)\n  product P$1\n  version $1\n  info [$2]",
        )
        .unwrap();
        let s = db.identify(0, b"ac\x01\x02 hi\xff").unwrap().service;
        assert_eq!(s.product.as_deref(), Some("P"));
        assert_eq!(s.version, None);
        assert_eq!(s.info.as_deref(), Some("[ hi\u{fffd}]"));
        let long = format!("ac{}", "y".repeat(500));
        let info = db
            .identify(0, long.as_bytes())
            .unwrap()
            .service
            .info
            .unwrap();
        assert_eq!(info.chars().count(), MAX_FIELD_LEN + 1);
    }

    #[test]
    fn unquotes_payloads() {
        assert_eq!(
            unquote(r#""a\r\n\x00\xFF\"\\""#).unwrap(),
            b"a\r\n\0\xff\"\\"
        );
        for bad in [r#"""#, r#""\q""#, r#""\x1""#, r#""a"b""#, "abc", r#""\""#] {
            assert!(unquote(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reports_errors_with_line_numbers() {
        let cases = [
            ("match x a", 1),
            ("probe a\nprobe a", 2),
            ("probe a\n  send @nope", 2),
            ("probe a\n  wait 5", 2),
            ("probe a\n  wait 0s", 2),
            ("probe a\n  ports 0", 2),
            ("probe a\nmatch x (", 2),
            ("probe a\nmatch x a\n  version $1", 3),
            ("probe a\nmatch x (a)\n  version $", 3),
            ("probe a\nmatch x a\n  confidence 11", 3),
            ("probe a\nmatch x a\n  send \"x\"", 3),
            ("probe a\n  fallback b", 2),
            ("probe a\n  colour blue", 2),
            ("probe a\n  product x", 2),
            ("probe a\nmatch x a\n  product a\n  product b", 4),
            ("probe a\n  send \"a\"\n  send \"b\"", 3),
            ("probe a b", 1),
            ("# empty", 0),
        ];
        for (src, line) in cases {
            let e = Database::parse(src).unwrap_err();
            assert_eq!(e.line, line, "{src:?}: {e}");
        }
    }

    #[test]
    fn builtin_database_parses() {
        let db = Database::parse(BUILTIN).unwrap_or_else(|e| panic!("probes.txt {e}"));
        assert!(db.probes.len() >= 10);
        assert!(db.rules().count() >= 60);
        let ids: Vec<usize> = db.rules().map(|r| r.id).collect();
        assert_eq!(ids, (0..ids.len()).collect::<Vec<_>>());
        for name in ["banner", "http-get", "tls", "generic-lines"] {
            assert!(db.probe(name).is_some(), "{name}");
        }
    }
}
