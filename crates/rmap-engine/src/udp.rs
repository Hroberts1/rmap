//! Unprivileged UDP probing, used when raw sockets aren't available.
//!
//! A connected UDP socket learns about ICMP port-unreachable replies: the
//! next `recv` fails with "connection refused" (Linux, macOS) or
//! "connection reset" (Windows). That is enough to tell closed ports from
//! the rest without root. It can't see other ICMP errors as precisely as
//! the raw backend, and the OS may rate-limit how fast they are reported.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use rmap_core::{PortResult, PortState, Protocol, Timing};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::Stats;
use crate::rtt::HostRtt;
use rmap_detect::udp::udp_payload;

/// How one UDP exchange ended.
#[derive(Debug)]
pub enum Outcome {
    /// The service answered.
    Reply(Duration),
    /// ICMP port unreachable came back.
    Refused(Duration),
    TimedOut,
    Failed(io::Error),
}

/// Sort the result of `recv` on a connected socket.
pub fn classify(result: io::Result<usize>, rtt: Duration) -> Outcome {
    match result {
        Ok(_) => Outcome::Reply(rtt),
        Err(e) if is_refusal(&e) => Outcome::Refused(rtt),
        Err(e) => Outcome::Failed(e),
    }
}

fn is_refusal(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
    )
}

async fn attempt(ip: IpAddr, port: u16, payload: &[u8], limit: Duration) -> Outcome {
    let local: SocketAddr = match ip {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = match UdpSocket::bind(local).await {
        Ok(s) => s,
        Err(e) => return Outcome::Failed(e),
    };
    if let Err(e) = socket.connect((ip, port)).await {
        return Outcome::Failed(e);
    }
    let started = Instant::now();
    if let Err(e) = socket.send(payload).await {
        return classify(Err(e), started.elapsed());
    }
    let mut buf = [0u8; 1500];
    match timeout(limit, socket.recv(&mut buf)).await {
        Ok(r) => classify(r, started.elapsed()),
        Err(_) => Outcome::TimedOut,
    }
}

/// Probe one UDP port. Silence after every retry means `OpenFiltered`.
/// Waits as long as the host's RTT estimate says, and feeds answers back.
pub async fn probe(
    ip: IpAddr,
    port: u16,
    timing: &Timing,
    stats: &Stats,
    host_rtt: &HostRtt,
) -> PortResult {
    let payload = udp_payload(port);
    for try_no in 0..=timing.retries {
        if !timing.scan_delay.is_zero() {
            sleep(timing.scan_delay).await;
        }
        let limit = host_rtt.timeout(timing, try_no);
        let outcome = attempt(ip, port, &payload, limit).await;
        rmap_log::trace!("udp probe {ip}:{port} try={try_no} limit={limit:?} outcome={outcome:?}");
        let (state, rtt) = match outcome {
            Outcome::Reply(rtt) => (PortState::Open, Some(rtt)),
            Outcome::Refused(rtt) => (PortState::Closed, Some(rtt)),
            Outcome::Failed(e) => {
                stats.record_error(ip, port, &e);
                (PortState::Filtered, None)
            }
            Outcome::TimedOut => continue,
        };
        // Each attempt uses a fresh socket, so its RTT is unambiguous.
        if let Some(rtt) = rtt {
            host_rtt.sample(rtt);
        }
        return PortResult::new(port, Protocol::Udp, state, rtt);
    }
    PortResult::new(port, Protocol::Udp, PortState::OpenFiltered, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_recv_results() {
        let rtt = Duration::from_millis(2);
        assert!(matches!(classify(Ok(10), rtt), Outcome::Reply(_)));
        assert!(matches!(classify(Ok(0), rtt), Outcome::Reply(_)));
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
        ] {
            assert!(matches!(
                classify(Err(kind.into()), rtt),
                Outcome::Refused(_)
            ));
        }
        assert!(matches!(
            classify(Err(io::ErrorKind::HostUnreachable.into()), rtt),
            Outcome::Failed(_)
        ));
    }

    fn quick() -> Timing {
        Timing {
            connect_timeout: Duration::from_millis(400),
            retries: 0,
            ..Timing::template(4)
        }
    }

    #[tokio::test]
    async fn answering_port_is_open() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(&buf[..n.max(1)], from).await;
            }
        });
        let r = probe(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            &quick(),
            &Stats::default(),
            &HostRtt::default(),
        )
        .await;
        assert_eq!(r.state, PortState::Open);
        assert_eq!(r.protocol, Protocol::Udp);
        assert!(r.rtt.is_some());
    }

    #[tokio::test]
    async fn silent_port_is_open_filtered() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let r = probe(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            &quick(),
            &Stats::default(),
            &HostRtt::default(),
        )
        .await;
        drop(server);
        assert_eq!(r.state, PortState::OpenFiltered);
        assert_eq!(r.rtt, None);
    }

    #[tokio::test]
    async fn unbound_port_is_closed() {
        let port = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap().port()
        };
        let timing = Timing {
            connect_timeout: Duration::from_secs(3),
            ..quick()
        };
        let r = probe(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            &timing,
            &Stats::default(),
            &HostRtt::default(),
        )
        .await;
        assert_eq!(r.state, PortState::Closed);
    }
}
