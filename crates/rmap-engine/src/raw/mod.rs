//! The raw-socket backend: SYN and UDP scans with hand-built packets, and
//! ICMP echo / ARP host discovery, over IPv4 and IPv6.
//!
//! Sockets are Linux-only (`cfg(target_os = "linux")`) and need root or
//! `CAP_NET_RAW`. Packet building and reply matching ([`matcher`]) work on
//! every platform so they can be tested anywhere.

pub mod matcher;

#[cfg(target_os = "linux")]
mod scanner;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub(crate) use scanner::RawScanner;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

pub use matcher::Route;

/// The route raw probes to `dst` take: `dst` and the local address the
/// kernel would send from, found by connecting a UDP socket (which sends
/// nothing) and reading its name.
pub fn route(dst: IpAddr) -> io::Result<Route> {
    let unspecified: IpAddr = match dst {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = UdpSocket::bind((unspecified, 0))?;
    socket.connect((dst, 9))?;
    match (socket.local_addr()?, dst) {
        (SocketAddr::V4(a), IpAddr::V4(dst)) if !a.ip().is_unspecified() => {
            Ok(Route::V4(*a.ip(), dst))
        }
        (SocketAddr::V6(a), IpAddr::V6(dst)) if !a.ip().is_unspecified() => {
            Ok(Route::V6(*a.ip(), dst))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no source address for this route",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_routes_from_loopback() {
        let r = route(Ipv4Addr::LOCALHOST.into()).unwrap();
        assert!(r.src().is_loopback(), "{r:?}");
        assert_eq!(r.dst(), IpAddr::from(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn v6_loopback_routes_from_loopback() {
        // Hosts and containers with IPv6 disabled can't bind at all.
        let Ok(r) = route(Ipv6Addr::LOCALHOST.into()) else {
            return;
        };
        assert_eq!(r, Route::V6(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST));
    }
}
