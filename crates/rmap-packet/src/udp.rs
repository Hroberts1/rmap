//! UDP headers (RFC 768).

use std::net::Ipv4Addr;

use crate::checksum::transport_checksum;
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
        let start = out.len();
        let len = (HEADER_LEN + payload.len()).min(usize::from(u16::MAX)) as u16;
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        let c = match transport_checksum(src, dst, PROTO_UDP, &out[start..]) {
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
