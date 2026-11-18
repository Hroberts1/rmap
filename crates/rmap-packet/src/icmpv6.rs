//! ICMPv6 (RFC 4443): the messages a port scan sends or gets back.
//!
//! Unlike ICMPv4, the checksum covers the IPv6 pseudo-header, so building
//! and verifying need the source and destination addresses.

use std::net::Ipv6Addr;

use crate::checksum::transport_checksum_v6;
use crate::ipv6::NEXT_ICMPV6;
use crate::{Result, be16, be32, need};

pub const TYPE_DEST_UNREACHABLE: u8 = 1;
pub const TYPE_PACKET_TOO_BIG: u8 = 2;
pub const TYPE_ECHO_REQUEST: u8 = 128;
pub const TYPE_ECHO_REPLY: u8 = 129;

/// Destination-unreachable code for "port unreachable" (3 in ICMPv4).
pub const CODE_PORT_UNREACHABLE: u8 = 4;

pub const HEADER_LEN: usize = 8;

/// A parsed ICMPv6 message. Borrowed slices point into the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Message<'a> {
    EchoRequest {
        id: u16,
        seq: u16,
        data: &'a [u8],
    },
    EchoReply {
        id: u16,
        seq: u16,
        data: &'a [u8],
    },
    /// `original` is as much of the offending IPv6 packet as fit.
    DestUnreachable {
        code: u8,
        original: &'a [u8],
    },
    PacketTooBig {
        mtu: u32,
        original: &'a [u8],
    },
    Other {
        kind: u8,
        code: u8,
        rest: [u8; 4],
        data: &'a [u8],
    },
}

impl<'a> Icmpv6Message<'a> {
    /// Parse a message. The checksum is not checked; see
    /// [`Icmpv6Message::checksum_valid`].
    pub fn parse(buf: &'a [u8]) -> Result<Icmpv6Message<'a>> {
        need(buf, HEADER_LEN)?;
        let (kind, code) = (buf[0], buf[1]);
        let body = &buf[HEADER_LEN..];
        let (id, seq) = (be16(buf, 4), be16(buf, 6));
        Ok(match kind {
            TYPE_ECHO_REQUEST => Icmpv6Message::EchoRequest {
                id,
                seq,
                data: body,
            },
            TYPE_ECHO_REPLY => Icmpv6Message::EchoReply {
                id,
                seq,
                data: body,
            },
            TYPE_DEST_UNREACHABLE => Icmpv6Message::DestUnreachable {
                code,
                original: body,
            },
            TYPE_PACKET_TOO_BIG => Icmpv6Message::PacketTooBig {
                mtu: be32(buf, 4),
                original: body,
            },
            _ => Icmpv6Message::Other {
                kind,
                code,
                rest: [buf[4], buf[5], buf[6], buf[7]],
                data: body,
            },
        })
    }

    /// Whether a whole message sent from `src` to `dst` carries a correct
    /// checksum.
    pub fn checksum_valid(src: Ipv6Addr, dst: Ipv6Addr, buf: &[u8]) -> bool {
        buf.len() >= HEADER_LEN && transport_checksum_v6(src, dst, NEXT_ICMPV6, buf) == 0
    }

    /// Append the message with its checksum computed for `src` -> `dst`.
    pub fn write(&self, src: Ipv6Addr, dst: Ipv6Addr, out: &mut Vec<u8>) {
        let start = out.len();
        let join = |id: u16, seq: u16| {
            let (i, s) = (id.to_be_bytes(), seq.to_be_bytes());
            [i[0], i[1], s[0], s[1]]
        };
        let (kind, code, rest, data): (u8, u8, [u8; 4], &[u8]) = match *self {
            Icmpv6Message::EchoRequest { id, seq, data } => {
                (TYPE_ECHO_REQUEST, 0, join(id, seq), data)
            }
            Icmpv6Message::EchoReply { id, seq, data } => (TYPE_ECHO_REPLY, 0, join(id, seq), data),
            Icmpv6Message::DestUnreachable { code, original } => {
                (TYPE_DEST_UNREACHABLE, code, [0; 4], original)
            }
            Icmpv6Message::PacketTooBig { mtu, original } => {
                (TYPE_PACKET_TOO_BIG, 0, mtu.to_be_bytes(), original)
            }
            Icmpv6Message::Other {
                kind,
                code,
                rest,
                data,
            } => (kind, code, rest, data),
        };
        out.extend_from_slice(&[kind, code, 0, 0]);
        out.extend_from_slice(&rest);
        out.extend_from_slice(data);
        let c = transport_checksum_v6(src, dst, NEXT_ICMPV6, &out[start..]);
        out[start + 2..start + 4].copy_from_slice(&c.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::PROTO_UDP;
    use crate::ipv6::Ipv6Header;
    use crate::udp::UdpHeader;

    const US: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const THEM: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    #[test]
    fn round_trips() {
        for msg in [
            Icmpv6Message::EchoRequest {
                id: 1,
                seq: 2,
                data: b"",
            },
            Icmpv6Message::EchoReply {
                id: 7,
                seq: 9,
                data: b"ping",
            },
            Icmpv6Message::DestUnreachable {
                code: 1,
                original: b"0123456789abcdefghijklmnopqrstuvwxyz0123456789",
            },
            Icmpv6Message::PacketTooBig {
                mtu: 1280,
                original: b"x",
            },
            Icmpv6Message::Other {
                kind: 135, // neighbour solicitation
                code: 0,
                rest: [0; 4],
                data: &[0xfe, 0x80],
            },
        ] {
            let mut buf = Vec::new();
            msg.write(US, THEM, &mut buf);
            assert!(Icmpv6Message::checksum_valid(US, THEM, &buf));
            assert!(
                !Icmpv6Message::checksum_valid(THEM, THEM, &buf),
                "the pseudo-header counts"
            );
            assert_eq!(Icmpv6Message::parse(&buf).unwrap(), msg);
        }
    }

    #[test]
    fn port_unreachable_quotes_the_probe() {
        let mut probe = Vec::new();
        Ipv6Header::new(US, THEM, PROTO_UDP, 64).write(8, &mut probe);
        UdpHeader::new(40000, 161).write_v6(US, THEM, &[], &mut probe);
        let mut buf = Vec::new();
        Icmpv6Message::DestUnreachable {
            code: CODE_PORT_UNREACHABLE,
            original: &probe,
        }
        .write(THEM, US, &mut buf);
        let Icmpv6Message::DestUnreachable { code, original } = Icmpv6Message::parse(&buf).unwrap()
        else {
            panic!("wrong type");
        };
        assert_eq!(code, CODE_PORT_UNREACHABLE);
        let (ip, inner) = Ipv6Header::parse(original).unwrap();
        assert_eq!((ip.src, ip.dst, ip.next_header), (US, THEM, PROTO_UDP));
        assert_eq!(UdpHeader::parse_ports(inner).unwrap(), (40000, 161));
    }

    #[test]
    fn short_messages_are_errors() {
        assert!(Icmpv6Message::parse(&[129, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(!Icmpv6Message::checksum_valid(US, THEM, &[0xff; 4]));
    }
}
