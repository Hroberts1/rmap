//! IPv6 fixed headers (RFC 8200).
//!
//! Extension headers are not walked: [`Ipv6Header::parse`] returns whatever
//! follows the fixed header, and `next_header` says what that is. rmap's
//! own probes carry none, so the copy quoted in an ICMPv6 error starts its
//! TCP or UDP header right after the fixed one.

use std::net::Ipv6Addr;

use crate::{Error, Result, be16, be32, need};

/// Next-header value for ICMPv6. TCP and UDP use the IPv4 protocol numbers
/// ([`crate::ipv4::PROTO_TCP`], [`crate::ipv4::PROTO_UDP`]).
pub const NEXT_ICMPV6: u8 = 58;

/// Length of the fixed header.
pub const HEADER_LEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    /// DSCP and ECN bits.
    pub traffic_class: u8,
    /// 20-bit flow label; higher bits are dropped when written.
    pub flow_label: u32,
    /// Length of everything after the fixed header, as received.
    /// [`Ipv6Header::write`] fills it in.
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl Ipv6Header {
    pub fn new(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, hop_limit: u8) -> Self {
        Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_len: 0,
            next_header,
            hop_limit,
            src,
            dst,
        }
    }

    /// Append the header for a payload of `payload_len` bytes.
    /// Payloads over 65,535 bytes (jumbograms) are not supported; the
    /// length field saturates.
    pub fn write(&self, payload_len: usize, out: &mut Vec<u8>) {
        let first = 6 << 28 | u32::from(self.traffic_class) << 20 | (self.flow_label & 0xf_ffff);
        let len = payload_len.min(usize::from(u16::MAX)) as u16;
        out.extend_from_slice(&first.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.push(self.next_header);
        out.push(self.hop_limit);
        out.extend_from_slice(&self.src.octets());
        out.extend_from_slice(&self.dst.octets());
    }

    /// Parse a fixed header and return it with its payload.
    ///
    /// The payload is cut at `payload_len`. It may be shorter than that,
    /// because the copy quoted in an ICMPv6 error is clipped.
    pub fn parse(buf: &[u8]) -> Result<(Ipv6Header, &[u8])> {
        need(buf, HEADER_LEN)?;
        let first = be32(buf, 0);
        if first >> 28 != 6 {
            return Err(Error::Invalid("IP version is not 6"));
        }
        let addr = |at: usize| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[at..at + 16]);
            Ipv6Addr::from(a)
        };
        let header = Ipv6Header {
            traffic_class: (first >> 20) as u8,
            flow_label: first & 0xf_ffff,
            payload_len: be16(buf, 4),
            next_header: buf[6],
            hop_limit: buf[7],
            src: addr(8),
            dst: addr(24),
        };
        let end = (HEADER_LEN + usize::from(header.payload_len)).min(buf.len());
        Ok((header, &buf[HEADER_LEN..end]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::PROTO_TCP;

    const A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const B: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    #[test]
    fn round_trip() {
        let mut h = Ipv6Header::new(A, B, PROTO_TCP, 64);
        h.traffic_class = 0xb8;
        h.flow_label = 0xabcde;
        let mut buf = Vec::new();
        h.write(4, &mut buf);
        assert_eq!(&buf[..4], &[0x6b, 0x8a, 0xbc, 0xde]);
        buf.extend_from_slice(b"data");
        let (back, payload) = Ipv6Header::parse(&buf).unwrap();
        assert_eq!(payload, b"data");
        assert_eq!(
            back,
            Ipv6Header {
                payload_len: 4,
                ..h
            }
        );
    }

    #[test]
    fn flow_label_is_masked() {
        let mut h = Ipv6Header::new(A, B, 59, 1);
        h.flow_label = u32::MAX;
        let mut buf = Vec::new();
        h.write(0, &mut buf);
        assert_eq!(buf[0] >> 4, 6, "version survives");
        assert_eq!(Ipv6Header::parse(&buf).unwrap().0.flow_label, 0xf_ffff);
    }

    #[test]
    fn payload_is_cut_at_payload_length() {
        let mut buf = Vec::new();
        Ipv6Header::new(A, B, PROTO_TCP, 64).write(2, &mut buf);
        buf.extend_from_slice(b"ab-padding");
        assert_eq!(Ipv6Header::parse(&buf).unwrap().1, b"ab");
        // A clipped quote still parses.
        assert_eq!(Ipv6Header::parse(&buf[..41]).unwrap().1, b"a");
    }

    #[test]
    fn rejects_bad_headers() {
        let mut buf = Vec::new();
        Ipv6Header::new(A, B, PROTO_TCP, 64).write(0, &mut buf);
        assert!(Ipv6Header::parse(&buf[..39]).is_err());
        assert!(Ipv6Header::parse(&[]).is_err());
        let mut v4 = buf.clone();
        v4[0] = 0x45;
        assert!(Ipv6Header::parse(&v4).is_err());
    }
}
