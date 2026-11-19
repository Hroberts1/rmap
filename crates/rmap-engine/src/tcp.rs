//! TCP connect probing. Works without root or raw sockets: the OS does the
//! three-way handshake, and we read the outcome from how `connect` returns.

use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rmap_core::{PortResult, PortState, Protocol, Timing};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::Stats;
use crate::rtt::HostRtt;

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
        let result = match timeout(limit, connect(ip, port)).await {
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

async fn connect(ip: IpAddr, port: u16) -> io::Result<TcpStream> {
    let socket = if ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    #[cfg(windows)]
    no_syn_retransmissions(&socket);
    socket.connect((ip, port).into()).await
}

/// Windows retries a SYN answered by RST and reports the refusal ~2 s later,
/// longer than the connect timeout, so closed ports looked filtered. Ask it
/// not to retransmit SYNs so a refusal arrives in one round trip. On a
/// Windows too old for the ioctl we keep the slow behaviour (see
/// [`SLOW_REFUSALS`]).
#[cfg(windows)]
fn no_syn_retransmissions(socket: &TcpSocket) {
    use std::os::windows::io::AsRawSocket;
    use std::sync::atomic::Ordering;

    // From mstcpip.h / Microsoft's SIO_TCP_INITIAL_RTO docs.
    const SIO_TCP_INITIAL_RTO: u32 = 0x9800_0011;
    const TCP_INITIAL_RTO_UNSPECIFIED_RTT: u16 = 0xFFFF;
    const TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS: u8 = 0xFE;
    #[repr(C)]
    struct TcpInitialRtoParameters {
        rtt: u16,
        max_syn_retransmissions: u8,
    }
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            s: usize,
            code: u32,
            in_buf: *const std::ffi::c_void,
            in_len: u32,
            out_buf: *mut std::ffi::c_void,
            out_len: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
            completion: *mut std::ffi::c_void,
        ) -> i32;
    }
    let params = TcpInitialRtoParameters {
        rtt: TCP_INITIAL_RTO_UNSPECIFIED_RTT,
        max_syn_retransmissions: TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS,
    };
    let mut returned = 0u32;
    // SAFETY: the socket is open for the duration of the call (we borrow
    // it), the input buffer is a live `repr(C)` struct of the size we pass,
    // there is no output buffer, and a null overlapped makes the call
    // synchronous so nothing outlives this frame.
    let rc = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_TCP_INITIAL_RTO,
            (&raw const params).cast(),
            size_of::<TcpInitialRtoParameters>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if !SLOW_REFUSALS.swap(true, Ordering::Relaxed) {
            rmap_log::debug!("SIO_TCP_INITIAL_RTO failed ({e}); using fixed connect timeouts");
        }
    }
}

/// Set when the OS delays refusals (Windows without `SIO_TCP_INITIAL_RTO`).
/// Its connect "RTTs" are then not network RTTs and adapted timeouts would
/// turn closed ports filtered, so probes keep the fixed template timeout.
static SLOW_REFUSALS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn adaptive_connect() -> bool {
    !SLOW_REFUSALS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Probe one port, retrying timeouts as the timing template allows. Waits
/// as long as the host's RTT estimate says, and feeds answers back to it.
pub async fn probe(
    ip: IpAddr,
    port: u16,
    timing: &Timing,
    stats: &Stats,
    host_rtt: &HostRtt,
) -> PortResult {
    for try_no in 0..=timing.retries {
        if !timing.scan_delay.is_zero() {
            sleep(timing.scan_delay).await;
        }
        let limit = if adaptive_connect() {
            host_rtt.timeout(timing, try_no)
        } else {
            timing.connect_timeout
        };
        let outcome = attempt(ip, port, limit, stats).await;
        rmap_log::trace!("probe {ip}:{port} try={try_no} limit={limit:?} outcome={outcome:?}");
        let (state, rtt) = match outcome {
            Outcome::Open(rtt) => (PortState::Open, Some(rtt)),
            Outcome::Refused(rtt) => (PortState::Closed, Some(rtt)),
            Outcome::Failed(e) => {
                stats.record_error(ip, port, &e);
                (PortState::Filtered, None)
            }
            Outcome::TimedOut => continue,
        };
        // Each attempt is a fresh connection, so its RTT is unambiguous.
        if let (true, Some(rtt)) = (adaptive_connect(), rtt) {
            host_rtt.sample(rtt);
        }
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

    /// A loopback port nothing listens on.
    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn refusal_is_reported_quickly() {
        let ip = IpAddr::from([127, 0, 0, 1]);
        let port = closed_port();
        let started = Instant::now();
        let outcome = attempt(ip, port, Duration::from_secs(5), &Stats::default()).await;
        let took = started.elapsed();
        eprintln!("refusal of {ip}:{port} took {took:?}");
        assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
        assert!(took < Duration::from_millis(500), "took {took:?}");
    }

    #[tokio::test]
    async fn closed_port_is_closed_not_filtered() {
        let ip = IpAddr::from([127, 0, 0, 1]);
        let started = Instant::now();
        let r = probe(
            ip,
            closed_port(),
            &Timing::template(3),
            &Stats::default(),
            &HostRtt::default(),
        )
        .await;
        assert_eq!(r.state, PortState::Closed);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn ping_answers_on_loopback() {
        // `ping` counts a refusal as up; `refusal_is_reported_quickly` covers
        // that path, since a discovery port may be listening here.
        let stats = std::sync::Arc::new(Stats::default());
        let started = Instant::now();
        let rtt = ping(IpAddr::from([127, 0, 0, 1]), &Timing::template(3), &stats).await;
        assert!(rtt.is_some());
        assert!(started.elapsed() < Duration::from_secs(1));
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
