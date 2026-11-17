//! TCP connect probing. Works without root or raw sockets: the OS does the
//! three-way handshake, and we read the outcome from how `connect` returns.

use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rmap_core::{PortResult, PortState, Protocol, Timing};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::Stats;

/// Ports tried during unprivileged host discovery. A host counts as up if
/// any of them accepts or actively refuses a connection.
pub const DISCOVERY_PORTS: &[u16] = &[80, 443, 22, 445, 3389];

/// How a single connection attempt ended.
#[derive(Debug)]
pub enum Outcome {
    Open(Duration),
    Refused(Duration),
    TimedOut,
    /// Unreachable, or another error that retrying won't fix.
    Failed(io::Error),
}

/// Sort a `connect` result into an outcome. `None` means a local resource
/// limit was hit and the attempt should simply be repeated.
pub fn classify(result: io::Result<()>, rtt: Duration) -> Option<Outcome> {
    match result {
        Ok(()) => Some(Outcome::Open(rtt)),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Some(Outcome::Refused(rtt)),
        Err(e) if out_of_sockets(&e) => None,
        Err(e) => Some(Outcome::Failed(e)),
    }
}

async fn attempt(ip: IpAddr, port: u16, limit: Duration, stats: &Stats) -> Outcome {
    loop {
        let started = Instant::now();
        let result = match timeout(limit, TcpStream::connect((ip, port))).await {
            Ok(r) => r.map(drop),
            Err(_) => return Outcome::TimedOut,
        };
        match classify(result, started.elapsed()) {
            Some(outcome) => return outcome,
            None => {
                // Too many sockets open locally; not a property of the target.
                if stats
                    .socket_backoffs
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    == 0
                {
                    rmap_log::warn!(
                        "hit the local socket limit probing {ip}:{port}; backing off. \
                         A lower timing template or a higher `ulimit -n` avoids this"
                    );
                }
                sleep(Duration::from_millis(25)).await;
            }
        }
    }
}

/// Probe one port, retrying timeouts as the timing template allows.
pub async fn probe(ip: IpAddr, port: u16, timing: &Timing, stats: &Stats) -> PortResult {
    for try_no in 0..=timing.retries {
        if !timing.scan_delay.is_zero() {
            sleep(timing.scan_delay).await;
        }
        let outcome = attempt(ip, port, timing.connect_timeout, stats).await;
        rmap_log::trace!("probe {ip}:{port} try={try_no} outcome={outcome:?}");
        let (state, rtt) = match outcome {
            Outcome::Open(rtt) => (PortState::Open, Some(rtt)),
            Outcome::Refused(rtt) => (PortState::Closed, Some(rtt)),
            Outcome::Failed(e) => {
                stats.record_error(ip, port, &e);
                (PortState::Filtered, None)
            }
            Outcome::TimedOut => continue,
        };
        return PortResult::new(port, Protocol::Tcp, state, rtt);
    }
    PortResult::new(port, Protocol::Tcp, PortState::Filtered, None)
}

/// Check whether a host is up. Returns the round-trip time of the first
/// answer, or `None` if nothing answered.
pub async fn ping(ip: IpAddr, timing: &Timing, stats: &std::sync::Arc<Stats>) -> Option<Duration> {
    let limit = timing.connect_timeout.max(Duration::from_secs(1));
    let mut tries = JoinSet::new();
    for &port in DISCOVERY_PORTS {
        let stats = stats.clone();
        tries.spawn(async move { (port, attempt(ip, port, limit, &stats).await) });
    }
    while let Some(done) = tries.join_next().await {
        match done {
            Ok((port, Outcome::Open(rtt) | Outcome::Refused(rtt))) => {
                rmap_log::trace!("ping {ip} answered on port {port} in {rtt:?}");
                return Some(rtt);
            }
            Ok((port, Outcome::Failed(e))) => stats.record_error(ip, port, &e),
            Ok((_, Outcome::TimedOut)) => {}
            Err(e) => rmap_log::error!("discovery task for {ip} failed: {e}"),
        }
    }
    None
}

fn out_of_sockets(e: &io::Error) -> bool {
    // EMFILE / ENFILE on Unix; WSAEMFILE / WSAENOBUFS on Windows.
    matches!(e.raw_os_error(), Some(23 | 24 | 10024 | 10055))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(code: i32) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(code))
    }

    #[test]
    fn classifies_connect_results() {
        let rtt = Duration::from_millis(3);
        assert!(matches!(classify(Ok(()), rtt), Some(Outcome::Open(d)) if d == rtt));
        assert!(matches!(
            classify(Err(io::ErrorKind::ConnectionRefused.into()), rtt),
            Some(Outcome::Refused(_))
        ));
        assert!(matches!(
            classify(Err(io::ErrorKind::HostUnreachable.into()), rtt),
            Some(Outcome::Failed(_))
        ));
        assert!(matches!(
            classify(Err(io::ErrorKind::PermissionDenied.into()), rtt),
            Some(Outcome::Failed(_))
        ));
    }

    #[test]
    fn socket_exhaustion_means_retry() {
        for code in [23, 24, 10024, 10055] {
            assert!(
                classify(os(code), Duration::ZERO).is_none(),
                "os error {code}"
            );
        }
    }
}
