//! TCP headers and options (RFC 9293, RFC 7323, RFC 2018).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::checksum::{transport_checksum, transport_checksum_v6};
use crate::ipv4::PROTO_TCP;
use crate::{Error, Result, be16, be32, need};

pub const MIN_HEADER_LEN: usize = 20;

/// The TCP control bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);
    pub const ECE: TcpFlags = TcpFlags(0x40);
    pub const CWR: TcpFlags = TcpFlags(0x80);

    /// Whether every bit in `other` is set.
    pub fn contains(self, other: TcpFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = TcpFlags;
    fn bitor(self, rhs: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    /// Kind 1, padding between options.
    Nop,
    /// Kind 2, maximum segment size.
    Mss(u16),
    /// Kind 3, window scale shift count.
    WindowScale(u8),
    /// Kind 4.
    SackPermitted,
    /// Kind 5, selective acknowledgement blocks (left, right edges).
    Sack(Vec<(u32, u32)>),
    /// Kind 8.
    Timestamps { value: u32, echo: u32 },
    /// Anything else, kept so it can be inspected or re-sent.
    Unknown { kind: u8, data: Vec<u8> },
}

impl TcpOption {
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            TcpOption::Nop => out.push(1),
            TcpOption::Mss(mss) => {
                out.extend_from_slice(&[2, 4]);
                out.extend_from_slice(&mss.to_be_bytes());
            }
            TcpOption::WindowScale(shift) => out.extend_from_slice(&[3, 3, *shift]),
            TcpOption::SackPermitted => out.extend_from_slice(&[4, 2]),
            TcpOption::Sack(blocks) => {
                let blocks = &blocks[..blocks.len().min(4)];
                out.extend_from_slice(&[5, 2 + 8 * blocks.len() as u8]);
                for (l, r) in blocks {
                    out.extend_from_slice(&l.to_be_bytes());
                    out.extend_from_slice(&r.to_be_bytes());
                }
            }
            TcpOption::Timestamps { value, echo } => {
                out.extend_from_slice(&[8, 10]);
                out.extend_from_slice(&value.to_be_bytes());
                out.extend_from_slice(&echo.to_be_bytes());
            }
            TcpOption::Unknown { kind, data } => {
                let data = &data[..data.len().min(38)];
                out.extend_from_slice(&[*kind, 2 + data.len() as u8]);
                out.extend_from_slice(data);
            }
        }
    }

    /// Parse an options area. Stops at end-of-list (kind 0).
    pub fn parse_all(mut buf: &[u8]) -> Result<Vec<TcpOption>> {
        let mut options = Vec::new();
        while let Some(&kind) = buf.first() {
            match kind {
                0 => break,
                1 => {
                    options.push(TcpOption::Nop);
                    buf = &buf[1..];
                    continue;
                }
                _ => {}
            }
            need(buf, 2)?;
            let len = usize::from(buf[1]);
            if len < 2 {
                return Err(Error::Invalid("TCP option length below 2"));
            }
            need(buf, len)?;
            let data = &buf[2..len];
            let fixed = |want: usize| {
                if data.len() == want {
                    Ok(())
                } else {
                    Err(Error::Invalid("TCP option has the wrong length"))
                }
            };
            options.push(match kind {
                2 => {
                    fixed(2)?;
                    TcpOption::Mss(be16(data, 0))
                }
                3 => {
                    fixed(1)?;
                    TcpOption::WindowScale(data[0])
                }
                4 => {
                    fixed(0)?;
                    TcpOption::SackPermitted
                }
                5 => {
                    if !data.len().is_multiple_of(8) {
                        return Err(Error::Invalid("SACK option length not a multiple of 8"));
                    }
                    TcpOption::Sack(
                        data.as_chunks::<8>()
                            .0
                            .iter()
                            .map(|c| (be32(c, 0), be32(c, 4)))
                            .collect(),
                    )
                }
                8 => {
                    fixed(8)?;
                    TcpOption::Timestamps {
                        value: be32(data, 0),
                        echo: be32(data, 4),
                    }
                }
                _ => TcpOption::Unknown {
                    kind,
                    data: data.to_vec(),
                },
            });
            buf = &buf[len..];
        }
        Ok(options)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    /// As received. [`TcpHeader::write`] computes a fresh one.
    pub checksum: u16,
    pub urgent: u16,
    pub options: Vec<TcpOption>,
}

impl TcpHeader {
    /// A SYN with the options a modern stack sends, so it looks ordinary.
    pub fn syn(src_port: u16, dst_port: u16, seq: u32) -> Self {
        TcpHeader {
            src_port,
            dst_port,
            seq,
            flags: TcpFlags::SYN,
            window: 1024,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamps { value: 0, echo: 0 },
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ],
            ..TcpHeader::default()
        }
    }

    /// Encoded options, padded with end-of-list bytes to a multiple of 4
    /// and cut at the 40-byte limit.
    fn encoded_options(&self) -> Vec<u8> {
        let mut opts = Vec::new();
        for o in &self.options {
            let before = opts.len();
            o.write(&mut opts);
            if opts.len() > 40 {
                opts.truncate(before);
                break;
            }
        }
        opts.resize(opts.len().div_ceil(4) * 4, 0);
        opts
    }

    /// Header length in bytes, including options.
    pub fn header_len(&self) -> usize {
        MIN_HEADER_LEN + self.encoded_options().len()
    }

    /// Append the header and `payload`, with the checksum computed over the
    /// IPv4 pseudo-header for `src` and `dst`.
    pub fn write(&self, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8], out: &mut Vec<u8>) {
        self.write_with(payload, out, |seg| {
            transport_checksum(src, dst, PROTO_TCP, seg)
        });
    }

    /// [`TcpHeader::write`] over the IPv6 pseudo-header.
    pub fn write_v6(&self, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8], out: &mut Vec<u8>) {
        self.write_with(payload, out, |seg| {
            transport_checksum_v6(src, dst, PROTO_TCP, seg)
        });
    }

    fn write_with(&self, payload: &[u8], out: &mut Vec<u8>, checksum: impl FnOnce(&[u8]) -> u16) {
        let start = out.len();
        let opts = self.encoded_options();
        let offset = ((MIN_HEADER_LEN + opts.len()) / 4) as u8;
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack.to_be_bytes());
        out.push(offset << 4);
        out.push(self.flags.0);
        out.extend_from_slice(&self.window.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.urgent.to_be_bytes());
        out.extend_from_slice(&opts);
        out.extend_from_slice(payload);
        let c = checksum(&out[start..]);
        out[start + 16..start + 18].copy_from_slice(&c.to_be_bytes());
    }

    /// Parse a segment, returning the header and its payload.
    pub fn parse(buf: &[u8]) -> Result<(TcpHeader, &[u8])> {
        need(buf, MIN_HEADER_LEN)?;
        let hlen = usize::from(buf[12] >> 4) * 4;
        if hlen < MIN_HEADER_LEN {
            return Err(Error::Invalid("TCP data offset below 5"));
        }
        need(buf, hlen)?;
        let header = TcpHeader {
            src_port: be16(buf, 0),
            dst_port: be16(buf, 2),
            seq: be32(buf, 4),
            ack: be32(buf, 8),
            flags: TcpFlags(buf[13]),
            window: be16(buf, 14),
            checksum: be16(buf, 16),
            urgent: be16(buf, 18),
            options: TcpOption::parse_all(&buf[MIN_HEADER_LEN..hlen])?,
        };
        Ok((header, &buf[hlen..]))
    }

    /// Ports and sequence number from the first 8 bytes of a segment: all
    /// that an ICMP error is guaranteed to quote.
    pub fn parse_prefix(buf: &[u8]) -> Result<(u16, u16, u32)> {
        need(buf, 8)?;
        Ok((be16(buf, 0), be16(buf, 2), be32(buf, 4)))
    }

    /// Whether `segment` (header and payload) carries a correct checksum.
    pub fn checksum_valid(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> bool {
        transport_checksum(src, dst, PROTO_TCP, segment) == 0
    }

    /// [`TcpHeader::checksum_valid`] over IPv6.
    pub fn checksum_valid_v6(src: Ipv6Addr, dst: Ipv6Addr, segment: &[u8]) -> bool {
        transport_checksum_v6(src, dst, PROTO_TCP, segment) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 2);
    const DST: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);

    #[test]
    fn syn_round_trip() {
        let h = TcpHeader::syn(40000, 443, 0xdead_beef);
        let mut buf = Vec::new();
        h.write(SRC, DST, &[], &mut buf);
        // 4 MSS + 2 SACK-permitted + 10 timestamps + 1 NOP + 3 wscale = 20.
        assert_eq!(buf.len(), 40);
        assert_eq!(buf[12], 0xa0);
        assert!(TcpHeader::checksum_valid(SRC, DST, &buf));
        let (back, payload) = TcpHeader::parse(&buf).unwrap();
        assert!(payload.is_empty());
        assert_eq!(
            TcpHeader {
                checksum: 0,
                ..back
            },
            h
        );
        assert_eq!(
            TcpHeader::parse_prefix(&buf).unwrap(),
            (40000, 443, 0xdead_beef)
        );
    }

    #[test]
    fn options_pad_and_sack_blocks() {
        let h = TcpHeader {
            flags: TcpFlags::ACK,
            options: vec![
                TcpOption::Sack(vec![(1, 2), (3, 4)]),
                TcpOption::Unknown {
                    kind: 30,
                    data: vec![9],
                },
            ],
            ..TcpHeader::default()
        };
        let mut buf = Vec::new();
        h.write(SRC, DST, b"hi", &mut buf);
        // 18 bytes of SACK + 3 unknown = 21, padded to 24.
        assert_eq!(h.header_len(), 44);
        let (back, payload) = TcpHeader::parse(&buf).unwrap();
        assert_eq!(payload, b"hi");
        assert_eq!(back.options, h.options);
        assert!(TcpHeader::checksum_valid(SRC, DST, &buf));
    }

    #[test]
    fn options_beyond_40_bytes_are_dropped() {
        let h = TcpHeader {
            options: vec![TcpOption::Timestamps { value: 1, echo: 2 }; 5],
            ..TcpHeader::default()
        };
        assert_eq!(h.header_len(), 60);
        let mut buf = Vec::new();
        h.write(SRC, DST, &[], &mut buf);
        assert_eq!(TcpHeader::parse(&buf).unwrap().0.options.len(), 4);
    }

    #[test]
    fn malformed_options_are_errors() {
        for bad in [
            &[2u8][..],       // kind with no length
            &[2, 1],          // length below 2
            &[2, 6, 0, 0],    // length past the end
            &[2, 3, 0],       // MSS with wrong length
            &[5, 5, 0, 0, 0], // SACK not a multiple of 8
            &[8, 4, 0, 0],    // timestamps too short
            &[3, 2],          // window scale missing its byte
            &[4, 3, 0],       // SACK-permitted with data
        ] {
            assert!(TcpOption::parse_all(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            TcpOption::parse_all(&[1, 1, 0, 2]).unwrap(),
            vec![TcpOption::Nop, TcpOption::Nop],
            "parsing stops at end-of-list"
        );
    }

    #[test]
    fn rejects_short_offsets() {
        let mut buf = Vec::new();
        TcpHeader::default().write(SRC, DST, &[], &mut buf);
        buf[12] = 0x40;
        assert!(TcpHeader::parse(&buf).is_err());
        buf[12] = 0x60; // claims 24 bytes, only 20 present
        assert!(TcpHeader::parse(&buf).is_err());
        assert!(TcpHeader::parse_prefix(&buf[..7]).is_err());
    }

    #[test]
    fn v6_checksum_uses_the_v6_pseudo_header() {
        let (a, b) = (
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        let h = TcpHeader::syn(40000, 443, 7);
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        h.write(SRC, DST, b"x", &mut v4);
        h.write_v6(a, b, b"x", &mut v6);
        assert_eq!(v4[..16], v6[..16], "only the checksum differs");
        assert_eq!(v4[18..], v6[18..]);
        assert!(TcpHeader::checksum_valid_v6(a, b, &v6));
        assert!(!TcpHeader::checksum_valid_v6(a, a, &v6));
        assert_eq!(TcpHeader::parse(&v6).unwrap().1, b"x");
    }

    #[test]
    fn flags() {
        let f = TcpFlags::SYN | TcpFlags::ACK;
        assert!(f.contains(TcpFlags::SYN));
        assert!(f.contains(TcpFlags::ACK));
        assert!(!f.contains(TcpFlags::RST));
        assert_eq!(f.0, 0x12);
    }
}
