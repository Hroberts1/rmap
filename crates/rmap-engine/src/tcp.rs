//! TCP connect probing. Works without root or raw sockets: the OS does the
//! three-way handshake, and we read the outcome from how `connect` returns.

use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rmap_core::{PortResult, PortState, Timing};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

/// Ports tried during unprivileged host discovery. A host counts as up if
/// any of them accepts or actively refuses a connection.
const DISCOVERY_PORTS: &[u16] = &[80, 443, 22, 445, 3389];

/// How a single connection attempt ended.
enum Outcome {
    Open(Duration),
    Refused(Duration),
    TimedOut,
    /// Unreachable, or another error that retrying won't fix.
    Failed,
}

async fn attempt(ip: IpAddr, port: u16, limit: Duration) -> Outcome {
    loop {
        let started = Instant::now();
        return match timeout(limit, TcpStream::connect((ip, port))).await {
            Ok(Ok(_stream)) => Outcome::Open(started.elapsed()),
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
                Outcome::Refused(started.elapsed())
            }
            Ok(Err(e)) if out_of_sockets(&e) => {
                // Local resource limit, not a property of the target.
                sleep(Duration::from_millis(25)).await;
                continue;
            }
            Ok(Err(_)) => Outcome::Failed,
            Err(_) => Outcome::TimedOut,
        };
    }
}

/// Probe one port, retrying timeouts as the timing template allows.
pub async fn probe(ip: IpAddr, port: u16, timing: &Timing) -> PortResult {
    for _ in 0..=timing.retries {
        if !timing.scan_delay.is_zero() {
            sleep(timing.scan_delay).await;
        }
        let (state, rtt) = match attempt(ip, port, timing.connect_timeout).await {
            Outcome::Open(rtt) => (PortState::Open, Some(rtt)),
            Outcome::Refused(rtt) => (PortState::Closed, Some(rtt)),
            Outcome::Failed => (PortState::Filtered, None),
            Outcome::TimedOut => continue,
        };
        return PortResult { port, state, rtt };
    }
    PortResult {
        port,
        state: PortState::Filtered,
        rtt: None,
    }
}

/// Check whether a host is up. Returns the round-trip time of the first
/// answer, or `None` if nothing answered.
pub async fn ping(ip: IpAddr, timing: &Timing) -> Option<Duration> {
    let limit = timing.connect_timeout.max(Duration::from_secs(1));
    let mut tries = JoinSet::new();
    for &port in DISCOVERY_PORTS {
        tries.spawn(attempt(ip, port, limit));
    }
    while let Some(done) = tries.join_next().await {
        if let Ok(Outcome::Open(rtt) | Outcome::Refused(rtt)) = done {
            return Some(rtt);
        }
    }
    None
}

fn out_of_sockets(e: &io::Error) -> bool {
    // EMFILE / ENFILE on Unix; WSAEMFILE / WSAENOBUFS on Windows.
    matches!(e.raw_os_error(), Some(23 | 24 | 10024 | 10055))
}
