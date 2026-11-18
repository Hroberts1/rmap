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

pub mod cpe;
pub mod db;
pub mod der;
pub mod pattern;
pub mod payloads;
pub mod tls;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod rule_tests;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use rmap_core::{DetectMethod, Protocol, Service, Timing, service_name};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
    Detector::builtin()
        .detect(SocketAddr::new(ip, port), protocol, timing, port)
        .await
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

    /// Detect the service at `addr`, choosing probes as if it were on
    /// `port` (normally `addr.port()`; tests use other values).
    pub async fn detect(
        &self,
        addr: SocketAddr,
        protocol: Protocol,
        timing: &Timing,
        port: u16,
    ) -> Option<Service> {
        if protocol != Protocol::Tcp {
            // UDP probes slot into the same database (`protocol udp`) once
            // the engine has a UDP transport for them.
            return port_table(port, None);
        }
        let started = Instant::now();
        let budget = budget(timing);
        let max_wait = timing
            .connect_timeout
            .saturating_mul(4)
            .max(Duration::from_secs(1));
        let mut unmatched: Option<Vec<u8>> = None;
        let mut failures = 0;
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
            match exchange(addr, &payload, connect, wait).await {
                Ok(response) => {
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
                    if let Some(service) = self.analyze(index, &response, port) {
                        rmap_log::debug!(
                            "service {addr}: {} {:?} via probe {} in {:?}",
                            service.name,
                            service.version_label(),
                            probe.name,
                            started.elapsed()
                        );
                        return Some(service);
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
        port_table(port, unmatched.as_deref())
    }
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

/// The guess from the port number, noting any reply nothing recognised.
fn port_table(port: u16, unmatched: Option<&[u8]>) -> Option<Service> {
    let name = service_name(port);
    if name.is_none() && unmatched.is_none() {
        return None;
    }
    Some(Service {
        name: name.unwrap_or("unknown").to_string(),
        info: unmatched.map(|r| format!("unrecognised reply: {}", escape(r, 48))),
        method: DetectMethod::PortTable,
        confidence: if name.is_some() { 3 } else { 0 },
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
        assert!(d.plan(53, Protocol::Udp).is_empty());
    }

    #[test]
    fn budget_scales_with_timing() {
        assert_eq!(budget(&Timing::template(3)), Duration::from_secs(15));
        assert_eq!(budget(&Timing::template(5)), Duration::from_secs(5));
        assert_eq!(budget(&Timing::template(0)), Duration::from_secs(30));
    }

    #[test]
    fn port_table_fallback() {
        let s = port_table(22, None).unwrap();
        assert_eq!(
            (s.name.as_str(), s.method, s.confidence),
            ("ssh", DetectMethod::PortTable, 3)
        );
        assert!(port_table(40000, None).is_none());
        let s = port_table(40000, Some(b"\x00hi\r\n")).unwrap();
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
