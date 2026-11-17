//! IPv4 headers (RFC 791).

use std::net::Ipv4Addr;

use crate::checksum::internet_checksum;
use crate::{Error, Result, be16, need};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Length of a header without options.
pub const MIN_HEADER_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    /// DSCP and ECN bits (the old type-of-service byte).
    pub tos: u8,
    /// Total length of header and payload. [`Ipv4Header::write`] fills it in.
    pub total_len: u16,
    pub id: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Fragment offset in 8-byte units.
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    /// As received. [`Ipv4Header::write`] computes a fresh one.
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// Raw option bytes. Padded with zeros to a multiple of 4 when written.
    pub options: Vec<u8>,
}

impl Ipv4Header {
    /// A typical header: DF set, no options.
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, ttl: u8, id: u16) -> Self {
        Ipv4Header {
            tos: 0,
            total_len: 0,
            id,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            ttl,
            protocol,
            checksum: 0,
            src,
            dst,
            options: Vec::new(),
        }
    }

    /// Header length in bytes, including padded options (at most 60).
    pub fn header_len(&self) -> usize {
        (MIN_HEADER_LEN + self.options.len().div_ceil(4) * 4).min(60)
    }

    /// Append the header for a payload of `payload_len` bytes, with the
    /// total length and checksum computed. Options beyond 40 bytes are cut.
    pub fn write(&self, payload_len: usize, out: &mut Vec<u8>) {
        let start = out.len();
        let hlen = self.header_len();
        let total = (hlen + payload_len).min(usize::from(u16::MAX)) as u16;
        let mut flags_frag = self.fragment_offset & 0x1fff;
        if self.dont_fragment {
            flags_frag |= 0x4000;
        }
        if self.more_fragments {
            flags_frag |= 0x2000;
        }
        out.push(0x40 | (hlen / 4) as u8);
        out.push(self.tos);
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags_frag.to_be_bytes());
        out.push(self.ttl);
        out.push(self.protocol);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.src.octets());
        out.extend_from_slice(&self.dst.octets());
        let opts = &self.options[..self.options.len().min(40)];
        out.extend_from_slice(opts);
        out.resize(start + hlen, 0);
        let c = internet_checksum(&out[start..start + hlen]);
        out[start + 10..start + 12].copy_from_slice(&c.to_be_bytes());
    }

    /// Parse a header and return it with its payload.
    ///
    /// The payload is cut at `total_len`. It may be shorter than `total_len`
    /// says, because the copy of a packet quoted inside an ICMP error carries
    /// only the first bytes of the original payload.
    pub fn parse(buf: &[u8]) -> Result<(Ipv4Header, &[u8])> {
        need(buf, MIN_HEADER_LEN)?;
        if buf[0] >> 4 != 4 {
            return Err(Error::Invalid("IP version is not 4"));
        }
        let hlen = usize::from(buf[0] & 0x0f) * 4;
        if hlen < MIN_HEADER_LEN {
            return Err(Error::Invalid("IPv4 header length below 20"));
        }
        need(buf, hlen)?;
        let total_len = be16(buf, 2);
        if usize::from(total_len) < hlen {
            return Err(Error::Invalid("IPv4 total length shorter than header"));
        }
        let flags_frag = be16(buf, 6);
        let ip = |at: usize| Ipv4Addr::new(buf[at], buf[at + 1], buf[at + 2], buf[at + 3]);
        let header = Ipv4Header {
            tos: buf[1],
            total_len,
            id: be16(buf, 4),
            dont_fragment: flags_frag & 0x4000 != 0,
            more_fragments: flags_frag & 0x2000 != 0,
            fragment_offset: flags_frag & 0x1fff,
            ttl: buf[8],
            protocol: buf[9],
            checksum: be16(buf, 10),
            src: ip(12),
            dst: ip(16),
            options: buf[MIN_HEADER_LEN..hlen].to_vec(),
        };
        let end = usize::from(total_len).min(buf.len());
        Ok((header, &buf[hlen..end]))
    }

    /// Whether the header checksum in `buf` (a whole header) is correct.
    pub fn checksum_valid(buf: &[u8]) -> bool {
        let Some(&first) = buf.first() else {
            return false;
        };
        let hlen = usize::from(first & 0x0f) * 4;
        hlen >= MIN_HEADER_LEN && buf.len() >= hlen && internet_checksum(&buf[..hlen]) == 0
    }

    /// Whether this is a fragment other than the first. Its payload does
    /// not start with a transport header.
    pub fn is_later_fragment(&self) -> bool {
        self.fragment_offset != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Ipv4Header {
        Ipv4Header::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            PROTO_UDP,
            64,
            0x1234,
        )
    }

    #[test]
    fn round_trip_with_checksum() {
        let mut buf = Vec::new();
        sample().write(4, &mut buf);
        buf.extend_from_slice(b"data");
        assert_eq!(buf.len(), 24);
        assert!(Ipv4Header::checksum_valid(&buf));
        let (h, payload) = Ipv4Header::parse(&buf).unwrap();
        assert_eq!(payload, b"data");
        assert_eq!(h.total_len, 24);
        assert_eq!(h.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(h.protocol, PROTO_UDP);
        assert!(h.dont_fragment && !h.more_fragments);
        assert_eq!(
            Ipv4Header {
                checksum: 0,
                total_len: 0,
                ..h
            },
            sample()
        );
    }

    #[test]
    fn options_are_padded() {
        let mut h = sample();
        h.options = vec![1, 1, 1]; // three NOPs
        assert_eq!(h.header_len(), 24);
        let mut buf = Vec::new();
        h.write(0, &mut buf);
        assert_eq!(buf[0], 0x46);
        assert_eq!(&buf[20..24], &[1, 1, 1, 0]);
        let (back, payload) = Ipv4Header::parse(&buf).unwrap();
        assert_eq!(back.options, vec![1, 1, 1, 0]);
        assert!(payload.is_empty());
        assert!(Ipv4Header::checksum_valid(&buf));
    }

    #[test]
    fn payload_is_cut_at_total_length() {
        let mut buf = Vec::new();
        sample().write(2, &mut buf);
        buf.extend_from_slice(b"ab-ethernet-padding");
        assert_eq!(Ipv4Header::parse(&buf).unwrap().1, b"ab");
        // A quoted header whose payload was clipped still parses.
        assert_eq!(Ipv4Header::parse(&buf[..21]).unwrap().1, b"a");
    }

    #[test]
    fn rejects_bad_headers() {
        let mut buf = Vec::new();
        sample().write(0, &mut buf);
        assert!(Ipv4Header::parse(&buf[..19]).is_err());
        let mut v6 = buf.clone();
        v6[0] = 0x65;
        assert!(Ipv4Header::parse(&v6).is_err());
        let mut short = buf.clone();
        short[0] = 0x44;
        assert!(Ipv4Header::parse(&short).is_err());
        let mut long = buf.clone();
        long[0] = 0x4f; // claims 60 bytes
        assert!(Ipv4Header::parse(&long).is_err());
        let mut tiny = buf.clone();
        tiny[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert!(Ipv4Header::parse(&tiny).is_err());
        let mut corrupt = buf.clone();
        corrupt[8] ^= 1;
        assert!(!Ipv4Header::checksum_valid(&corrupt));
        assert!(!Ipv4Header::checksum_valid(&[]));
    }
}
