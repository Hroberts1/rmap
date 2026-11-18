//! Packet building and parsing for rmap, written from scratch.
//!
//! Covers Ethernet II, ARP (Ethernet/IPv4), IPv4, IPv6, TCP (with options),
//! UDP, ICMPv4 and ICMPv6, plus RFC 1071 internet checksums over the IPv4
//! and IPv6 pseudo-headers.
//!
//! Every parser takes untrusted bytes straight off the wire. Parsers never
//! panic: truncated or malformed input returns an [`Error`]. Builders append
//! to a caller-owned `Vec<u8>` so one buffer can be reused per packet.

pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

pub use arp::ArpPacket;
pub use checksum::{internet_checksum, transport_checksum, transport_checksum_v6};
pub use ethernet::{EthernetHeader, MacAddr};
pub use icmp::IcmpMessage;
pub use icmpv6::Icmpv6Message;
pub use ipv4::Ipv4Header;
pub use ipv6::Ipv6Header;
pub use tcp::{TcpFlags, TcpHeader, TcpOption};
pub use udp::UdpHeader;

/// Why a packet could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The buffer ended before the structure did.
    Truncated { needed: usize, got: usize },
    /// A field holds a value this parser cannot accept.
    Invalid(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated { needed, got } => {
                write!(f, "packet truncated: needed {needed} bytes, got {got}")
            }
            Error::Invalid(what) => write!(f, "invalid packet: {what}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Fail unless `buf` holds at least `needed` bytes.
pub(crate) fn need(buf: &[u8], needed: usize) -> Result<()> {
    if buf.len() < needed {
        Err(Error::Truncated {
            needed,
            got: buf.len(),
        })
    } else {
        Ok(())
    }
}

/// Read a big-endian u16 at `at`. Callers check the length first.
pub(crate) fn be16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

/// Read a big-endian u32 at `at`. Callers check the length first.
pub(crate) fn be32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}
