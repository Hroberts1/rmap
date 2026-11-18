//! UDP headers (RFC 768).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::checksum::{transport_checksum, transport_checksum_v6};
use crate::ipv4::PROTO_UDP;
use crate::{Error, Result, be16, need};

pub const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    /// Header plus payload, as received. [`UdpHeader::write`] fills it in.
    pub length: u16,
    /// As received; 0 means the sender did not compute one.
    pub checksum: u16,
}

impl UdpHeader {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        UdpHeader {
            src_port,
            dst_port,
            ..UdpHeader::default()
        }
    }

    /// Append the header and `payload` with length and checksum computed.
    pub fn write(&self, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8], out: &mut Vec<u8>) {
        self.write_with(payload, out, |d| transport_checksum(src, dst, PROTO_UDP, d));
    }

    /// [`UdpHeader::write`] over the IPv6 pseudo-header.
    pub fn write_v6(&self, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8], out: &mut Vec<u8>) {
        self.write_with(payload, out, |d| {
            transport_checksum_v6(src, dst, PROTO_UDP, d)
        });
    }

    fn write_with(&self, payload: &[u8], out: &mut Vec<u8>, checksum: impl FnOnce(&[u8]) -> u16) {
        let start = out.len();
        let len = (HEADER_LEN + payload.len()).min(usize::from(u16::MAX)) as u16;
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        let c = match checksum(&out[start..]) {
            0 => 0xffff, // 0 means "no checksum", so send its other form
            c => c,
        };
        out[start + 6..start + 8].copy_from_slice(&c.to_be_bytes());
    }

    /// Parse a datagram. The payload is cut at the header's length field.
    pub fn parse(buf: &[u8]) -> Result<(UdpHeader, &[u8])> {
        need(buf, HEADER_LEN)?;
        let header = UdpHeader {
            src_port: be16(buf, 0),
            dst_port: be16(buf, 2),
            length: be16(buf, 4),
            checksum: be16(buf, 6),
        };
        let len = usize::from(header.length);
        if len < HEADER_LEN {
            return Err(Error::Invalid("UDP length below 8"));
        }
        need(buf, len)?;
        Ok((header, &buf[HEADER_LEN..len]))
    }

    /// Ports from the first 4 bytes of a datagram, as quoted in ICMP errors.
    pub fn parse_ports(buf: &[u8]) -> Result<(u16, u16)> {
        need(buf, 4)?;
        Ok((be16(buf, 0), be16(buf, 2)))
    }

    /// Whether `datagram` carries a correct checksum. A zero checksum means
    /// none was sent, which is allowed over IPv4.
    pub fn checksum_valid(src: Ipv4Addr, dst: Ipv4Addr, datagram: &[u8]) -> bool {
        datagram.get(6..8) == Some(&[0, 0])
            || transport_checksum(src, dst, PROTO_UDP, datagram) == 0
    }

    /// Whether `datagram` carries a correct checksum over IPv6, where it is
    /// mandatory: a zero checksum is invalid (RFC 8200 section 8.1).
    pub fn checksum_valid_v6(src: Ipv6Addr, dst: Ipv6Addr, datagram: &[u8]) -> bool {
        datagram.get(6..8).is_some_and(|c| c != [0, 0])
            && transport_checksum_v6(src, dst, PROTO_UDP, datagram) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(10, 1, 1, 1);
    const B: Ipv4Addr = Ipv4Addr::new(10, 1, 1, 2);

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        UdpHeader::new(5353, 53).write(A, B, b"query", &mut buf);
        assert_eq!(buf.len(), 13);
        assert!(UdpHeader::checksum_valid(A, B, &buf));
        let (h, payload) = UdpHeader::parse(&buf).unwrap();
        assert_eq!((h.src_port, h.dst_port, h.length), (5353, 53, 13));
        assert_eq!(payload, b"query");
        assert_eq!(UdpHeader::parse_ports(&buf).unwrap(), (5353, 53));
    }

    #[test]
    fn length_field_is_enforced() {
        let mut buf = Vec::new();
        UdpHeader::new(1, 2).write(A, B, b"abc", &mut buf);
        assert!(UdpHeader::parse(&buf[..10]).is_err(), "claims 11 bytes");
        let mut short = buf.clone();
        short[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert!(UdpHeader::parse(&short).is_err());
        buf.extend_from_slice(b"trailing");
        assert_eq!(UdpHeader::parse(&buf).unwrap().1, b"abc");
    }

    #[test]
    fn v6_checksum_is_mandatory() {
        let (a, b) = (
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        let mut buf = Vec::new();
        UdpHeader::new(1, 2).write_v6(a, b, b"x", &mut buf);
        assert!(UdpHeader::checksum_valid_v6(a, b, &buf));
        assert!(!UdpHeader::checksum_valid_v6(a, a, &buf));
        buf[6..8].copy_from_slice(&[0, 0]);
        assert!(!UdpHeader::checksum_valid_v6(a, b, &buf));
        assert!(!UdpHeader::checksum_valid_v6(a, b, &buf[..5]));
    }

    #[test]
    fn zero_checksum_means_none() {
        let mut buf = Vec::new();
        UdpHeader::new(1, 2).write(A, B, b"x", &mut buf);
        buf[6] = 0;
        buf[7] = 0;
        assert!(UdpHeader::checksum_valid(A, B, &buf));
        buf[6] = 1;
        assert!(!UdpHeader::checksum_valid(A, B, &buf));
    }
}
