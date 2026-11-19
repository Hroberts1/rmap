//! Service and version detection for rmap.
//!
//! [`detect`] connects to an open port, sends probes from rmap's own probe
//! database ([`db`], `probes.txt`) and matches the replies against rules
//! written in a small linear-time pattern language ([`pattern`]). TLS
//! replies are decoded in code ([`tls`], [`der`]) to report the protocol
//! version and certificate names. Recognised products get CPE 2.3 names
//! ([`cpe`]) for vulnerability matching.
//!
//! Probes are chosen by port: those that list the port go first, then the
//! `generic` ones (banner wait, HTTP, TLS, blank lines). Each probe uses a
//! fresh connection, and the whole port is bounded by a time budget derived
//! from the timing template. When nothing matches, the result falls back to
//! the port-number table with low confidence.
//!
//! UDP ports get the `protocol udp` probes over a connected UDP socket, one
//! datagram each way. Their binary replies are decoded in code ([`udp`]).

pub mod cpe;
pub mod db;
pub mod der;
pub mod http;
pub mod pattern;
pub mod payloads;
pub mod tls;
pub mod udp;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod rule_tests;
#[cfg(test)]
mod udp_e2e_tests;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use rmap_core::{DetectMethod, Protocol, SILENT_INFO, Service, Timing, service_name};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout, timeout_at};

use db::{Builtin, Database, Payload};

/// Most bytes read from one probe's response.
pub const MAX_RESPONSE: usize = 16 * 1024;
/// Once data has arrived, stop reading after this long without more.
const IDLE_GAP: Duration = Duration::from_millis(500);
/// Bytes of a raw response shown in trace logs and unmatched-port info.
const SNIPPET: usize = 160;

/// Port-table names that already mean "this protocol over TLS".
const TLS_NAMES: &[&str] = &[
    "https",
    "smtps",
    "ldaps",
    "ftps",
    "imaps",
    "pop3s",
    "sips",
    "winrm-https",
    "docker-tls",
    "kube-api",
];

/// Identify the service on an open port using the built-in database.
///
/// Returns `None` only when nothing at all is known: no probe got an
/// answer and the port number isn't in the port table.
pub async fn detect(ip: IpAddr, port: u16, protocol: Protocol, timing: &Timing) -> Option<Service> {
    detect_port(ip, port, protocol, timing).await.service
}

/// Like [`detect`], also saying whether any probe got a reply.
pub async fn detect_port(ip: IpAddr, port: u16, protocol: Protocol, timing: &Timing) -> Detected {
    Detector::builtin()
        .detect_port(SocketAddr::new(ip, port), protocol, timing, port)
        .await
}

/// What detection learned about one port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detected {
    pub service: Option<Service>,
    /// Some probe got a reply. For UDP that proves the port open.
    pub answered: bool,
}

/// A parsed probe database and the logic to run it.
#[derive(Debug, Clone)]
pub struct Detector {
    db: Database,
}

impl Detector {
    pub fn new(db: Database) -> Detector {
        Detector { db }
    }

    /// The database shipped in `probes.txt`, parsed on first use.
    pub fn builtin() -> &'static Detector {
        static BUILTIN: OnceLock<Detector> = OnceLock::new();
        BUILTIN.get_or_init(|| match Database::parse(db::BUILTIN) {
            Ok(db) => {
                rmap_log::debug!(
                    "service database: {} probes, {} rules",
                    db.probes.len(),
                    db.rules().count()
                );
                Detector::new(db)
            }
            Err(e) => {
                // Caught by tests; never expected in a release.
                rmap_log::error!("built-in service database is invalid: {e}");
                Detector::new(Database::default())
            }
        })
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Probe indices to try on `port`, in order: probes that list the port,
    /// then generic probes.
    pub fn plan(&self, port: u16, protocol: Protocol) -> Vec<usize> {
        let probes = &self.db.probes;
        let ours = |i: &usize| probes[*i].protocol == protocol;
        let mut plan: Vec<usize> = (0..probes.len())
            .filter(ours)
            .filter(|&i| probes[i].likely_on(port))
            .collect();
        for i in (0..probes.len()).filter(ours) {
            if probes[i].generic && !plan.contains(&i) {
                plan.push(i);
            }
        }
        plan
    }

    /// Identify what answered probe `index` with `response`. Pure: no I/O.
    /// `port` is used to name TLS services.
    pub fn analyze(&self, index: usize, response: &[u8], port: u16) -> Option<Service> {
        let probe = self.db.probes.get(index)?;
        if probe.payload == Payload::Builtin(Builtin::TlsClientHello)
            && let Some(info) = tls::analyze(response)
        {
            return Some(tls_service(&info, port));
        }
        if let Payload::Builtin(b) = probe.payload
            && let Some(decode) = udp::decoder(b)
        {
            return Some(self.refine(index, decode(response)?));
        }
        let m = self.db.identify(index, response)?;
        rmap_log::debug!(
            "rule at probes.txt:{} ({}) matched the {} response",
            m.rule.line,
            m.probe.name,
            probe.name
        );
        let mut service = m.service;
        if m.probe.payload == Payload::None {
            service.method = DetectMethod::Banner;
        }
        service.cpes = cpe::for_service(&service);
        Some(service)
    }

    /// Let the probe's rules name the product from the text a UDP decoder
    /// found; the decoder's own summary stays unless a rule sets `info`.
    fn refine(&self, index: usize, decoded: udp::Decoded) -> Service {
        let mut service = decoded.service;
        if let Some(text) = &decoded.text
            && let Some(m) = self.db.identify(index, text)
        {
            rmap_log::debug!("rule at probes.txt:{} matched decoded text", m.rule.line);
            let rule = m.service;
            service.product = rule.product;
            service.version = rule.version;
            service.os_hint = rule.os_hint.or(service.os_hint);
            service.info = rule.info.or(service.info);
            service.confidence = service.confidence.max(rule.confidence);
        }
        service.cpes = cpe::for_service(&service);
        service
    }

    /// Detect the service at `addr`, choosing probes as if it were on
    /// `port` (normally `addr.port()`; tests use other values).
    pub async fn detect(
        &self,
        addr: SocketAddr,
        protocol: Protocol,
        timing: &Timing,
        port: u16,
    ) -> Option<Service> {
        self.detect_port(addr, protocol, timing, port).await.service
    }

    /// Like [`Detector::detect`], also saying whether any probe got a reply.
    pub async fn detect_port(
        &self,
        addr: SocketAddr,
        protocol: Protocol,
        timing: &Timing,
        port: u16,
    ) -> Detected {
        let started = Instant::now();
        let budget = budget(timing);
        let max_wait = timing
            .connect_timeout
            .saturating_mul(4)
            .max(Duration::from_secs(1));
        let mut unmatched: Option<Vec<u8>> = None;
        let mut failures = 0;
        let mut answered = false;
        // Some probe connected; with nothing answered, the port is silent.
        let mut connected = false;
        for index in self.plan(port, protocol) {
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                rmap_log::debug!("service {addr}: time budget of {budget:?} used up");
                break;
            }
            let probe = &self.db.probes[index];
            let payload = match &probe.payload {
                Payload::None => Vec::new(),
                Payload::Bytes(b) => b.clone(),
                Payload::Builtin(b) => payloads::build(*b),
            };
            let wait = probe.wait.min(max_wait).min(remaining);
            let connect = timing.connect_timeout.min(remaining);
            let reply = match protocol {
                Protocol::Tcp => exchange(addr, &payload, connect, wait).await,
                Protocol::Udp => exchange_udp(addr, &payload, wait).await,
            };
            match reply {
                Ok(response) => {
                    connected = true;
                    rmap_log::trace!(
                        "service {addr}: probe {} got {} bytes: {}",
                        probe.name,
                        response.len(),
                        escape(&response, SNIPPET)
                    );
                    if response.is_empty() {
                        rmap_log::debug!("service {addr}: probe {} got no reply", probe.name);
                        continue;
                    }
                    answered = true;
                    if let Some(mut service) = self.analyze(index, &response, port) {
                        if response.starts_with(b"HTTP/") {
                            let remaining = budget.saturating_sub(started.elapsed());
                            let wait = probe.wait.min(max_wait).min(remaining);
                            let connect = timing.connect_timeout.min(remaining);
                            add_title(&mut service, &response, addr, connect, wait).await;
                        }
                        rmap_log::debug!(
                            "service {addr}: {} {:?} via probe {} in {:?}",
                            service.name,
                            service.version_label(),
                            probe.name,
                            started.elapsed()
                        );
                        return Detected {
                            service: Some(service),
                            answered,
                        };
                    }
                    rmap_log::debug!("service {addr}: probe {} reply unrecognised", probe.name);
                    unmatched.get_or_insert(response);
                }
                Err(e) => {
                    rmap_log::debug!("service {addr}: probe {} failed: {e}", probe.name);
                    failures += 1;
                    // The port stopped accepting; more probes won't help.
                    if failures >= 2 {
                        break;
                    }
                }
            }
        }
        rmap_log::debug!("service {addr}: no rule matched; using the port table");
        // UDP silence is normal (open|filtered), so only TCP is marked.
        let silent = protocol == Protocol::Tcp && connected && !answered;
        Detected {
            service: port_table(port, unmatched.as_deref(), silent),
            answered,
        }
    }
}

/// Add the page title of an HTTP response to `service`, following one
/// same-host redirect when the first page has none.
async fn add_title(
    service: &mut Service,
    response: &[u8],
    addr: SocketAddr,
    connect: Duration,
    wait: Duration,
) {
    let mut title = http::title(response);
    if title.is_none()
        && !wait.is_zero()
        && let Some(path) = http::redirect(response, addr)
    {
        rmap_log::debug!("service {addr}: following redirect to {path}");
        if let Ok(page) = exchange(addr, &http::request(&path), connect, wait).await {
            title = http::title(&page);
        }
    }
    let Some(title) = title else { return };
    if service.product.is_none() {
        service.product = http::product(&title).map(String::from);
    }
    service.info = http::with_title(service.info.take(), &title);
}

/// Total time allowed for one port: ten connect timeouts, 5-30 s.
pub fn budget(timing: &Timing) -> Duration {
    timing
        .connect_timeout
        .saturating_mul(10)
        .clamp(Duration::from_secs(5), Duration::from_secs(30))
}

/// Connect, send `payload` (if any) and read until EOF, the size cap, a
/// pause after data, or `wait` runs out.
async fn exchange(
    addr: SocketAddr,
    payload: &[u8],
    connect: Duration,
    wait: Duration,
) -> io::Result<Vec<u8>> {
    let mut stream = timeout(connect, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
    let deadline = Instant::now() + wait;
    if !payload.is_empty() {
        // A server that talks first may close before reading; still read
        // whatever it sent.
        let _ = timeout_at(deadline, stream.write_all(payload)).await;
    }
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let limit = if response.is_empty() {
            deadline
        } else {
            deadline.min(Instant::now() + IDLE_GAP)
        };
        match timeout_at(limit, stream.read(&mut chunk)).await {
            Err(_) | Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let take = n.min(MAX_RESPONSE - response.len());
                response.extend_from_slice(&chunk[..take]);
                if response.len() >= MAX_RESPONSE {
                    break;
                }
            }
            Ok(Err(e)) if response.is_empty() && e.kind() != io::ErrorKind::ConnectionReset => {
                return Err(e);
            }
            Ok(Err(_)) => break,
        }
    }
    Ok(response)
}

/// Send one datagram on a connected socket and wait up to `wait` for the
/// first reply. An ICMP port unreachable surfaces as an error.
// shortcut: one datagram per probe, no retransmit; the port scan already
// retried, so loss here only costs the version, not the port state.
async fn exchange_udp(addr: SocketAddr, payload: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
    let local: SocketAddr = match addr {
        SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(addr).await?;
    socket.send(payload).await?;
    let mut buf = vec![0u8; MAX_RESPONSE];
    match timeout(wait, socket.recv(&mut buf)).await {
        Err(_) => Ok(Vec::new()),
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        }
        Ok(Err(e)) => Err(e),
    }
}

fn tls_service(info: &tls::TlsInfo, port: u16) -> Service {
    let name = match service_name(port) {
        Some(n) if TLS_NAMES.contains(&n) => n.to_string(),
        Some(n) => format!("tls/{n}"),
        None => "tls".to_string(),
    };
    Service {
        name,
        info: Some(info.summary()),
        method: DetectMethod::Probe,
        confidence: if info.version.is_some() { 8 } else { 7 },
        ..Default::default()
    }
}

/// The guess from the port number, noting any reply nothing recognised,
/// or that the port accepted connections but stayed `silent`.
fn port_table(port: u16, unmatched: Option<&[u8]>, silent: bool) -> Option<Service> {
    let name = service_name(port);
    if name.is_none() && unmatched.is_none() && !silent {
        return None;
    }
    let info = match unmatched {
        Some(r) => Some(format!("unrecognised reply: {}", escape(r, 48))),
        None => silent.then(|| SILENT_INFO.to_string()),
    };
    Some(Service {
        name: name.unwrap_or("unknown").to_string(),
        info,
        method: DetectMethod::PortTable,
        confidence: match (name, silent) {
            (None, _) => 0,
            (Some(_), true) => 1,
            (Some(_), false) => 3,
        },
        ..Default::default()
    })
}

/// Printable, length-capped rendering of raw bytes for logs and the UI.
pub fn escape(bytes: &[u8], max: usize) -> String {
    let mut out = String::new();
    for &b in bytes.iter().take(max) {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    if bytes.len() > max {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_put_port_specific_probes_first() {
        let d = Detector::builtin();
        let names = |port| {
            d.plan(port, Protocol::Tcp)
                .into_iter()
                .map(|i| d.database().probes[i].name.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(6379)[0], "redis");
        assert_eq!(names(443)[0], "tls");
        assert_eq!(names(22)[0], "banner");
        assert_eq!(names(80)[0], "http-get");
        assert_eq!(names(40000), ["banner", "http-get", "tls", "generic-lines"]);
        let udp = |port| {
            d.plan(port, Protocol::Udp)
                .into_iter()
                .map(|i| d.database().probes[i].name.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(udp(53), ["dns-version"]);
        assert_eq!(udp(123), ["ntp-readvar", "ntp-client"]);
        assert_eq!(udp(161), ["snmp-v2c", "snmp-v1"]);
        assert!(udp(40000).is_empty(), "no generic UDP probes");
    }

    #[test]
    fn budget_scales_with_timing() {
        assert_eq!(budget(&Timing::template(3)), Duration::from_secs(15));
        assert_eq!(budget(&Timing::template(5)), Duration::from_secs(5));
        assert_eq!(budget(&Timing::template(0)), Duration::from_secs(30));
    }

    #[test]
    fn port_table_fallback() {
        let s = port_table(22, None, false).unwrap();
        assert_eq!(
            (s.name.as_str(), s.method, s.confidence),
            ("ssh", DetectMethod::PortTable, 3)
        );
        assert!(port_table(40000, None, false).is_none());
        let s = port_table(40000, Some(b"\x00hi\r\n"), false).unwrap();
        assert_eq!(s.name, "unknown");
        assert_eq!(s.info.as_deref(), Some("unrecognised reply: \\x00hi\\r\\n"));
    }

    #[test]
    fn tls_names() {
        let info = tls::TlsInfo {
            version: Some("TLSv1.2"),
            ..Default::default()
        };
        assert_eq!(tls_service(&info, 443).name, "https");
        assert_eq!(tls_service(&info, 8080).name, "tls/http");
        assert_eq!(tls_service(&info, 40000).name, "tls");
    }

    #[test]
    fn escapes() {
        assert_eq!(escape(b"a\\b\xff", 10), "a\\\\b\\xff");
        assert_eq!(escape(b"abcdef", 3), "abc…");
    }
}
