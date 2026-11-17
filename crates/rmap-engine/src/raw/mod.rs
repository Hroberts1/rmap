//! The raw-socket backend: SYN and UDP scans with hand-built packets, and
//! ICMP echo / ARP host discovery.
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
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

/// The local address the kernel would use to reach `dst`, found by
/// connecting a UDP socket (which sends nothing) and reading its name.
pub fn route_source(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((dst, 9))?;
    match socket.local_addr()? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() => Ok(*a.ip()),
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no IPv4 source address for this route",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_routes_from_loopback() {
        let src = route_source(Ipv4Addr::LOCALHOST).unwrap();
        assert!(src.is_loopback(), "{src}");
    }
}
