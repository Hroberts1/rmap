//! ICMPv4 (RFC 792).

use crate::checksum::internet_checksum;
use crate::{Result, be16, need};

pub const TYPE_ECHO_REPLY: u8 = 0;
pub const TYPE_DEST_UNREACHABLE: u8 = 3;
pub const TYPE_ECHO_REQUEST: u8 = 8;
pub const TYPE_TIME_EXCEEDED: u8 = 11;

/// Destination-unreachable code for "port unreachable".
pub const CODE_PORT_UNREACHABLE: u8 = 3;

pub const HEADER_LEN: usize = 8;

/// A parsed ICMPv4 message. Borrowed slices point into the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpMessage<'a> {
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
    /// `original` is the quoted IPv4 header and at least 8 bytes of the
    /// datagram that triggered the error.
    DestUnreachable {
        code: u8,
        original: &'a [u8],
    },
    TimeExceeded {
        code: u8,
        original: &'a [u8],
    },
    Other {
        kind: u8,
        code: u8,
        rest: [u8; 4],
        data: &'a [u8],
    },
}

impl<'a> IcmpMessage<'a> {
    /// Parse a message. The checksum is not checked; see
    /// [`IcmpMessage::checksum_valid`].
    pub fn parse(buf: &'a [u8]) -> Result<IcmpMessage<'a>> {
        need(buf, HEADER_LEN)?;
        let (kind, code) = (buf[0], buf[1]);
        let body = &buf[HEADER_LEN..];
        let (id, seq) = (be16(buf, 4), be16(buf, 6));
        Ok(match kind {
            TYPE_ECHO_REQUEST => IcmpMessage::EchoRequest {
                id,
                seq,
                data: body,
            },
            TYPE_ECHO_REPLY => IcmpMessage::EchoReply {
                id,
                seq,
                data: body,
            },
            TYPE_DEST_UNREACHABLE => IcmpMessage::DestUnreachable {
                code,
                original: body,
            },
            TYPE_TIME_EXCEEDED => IcmpMessage::TimeExceeded {
                code,
                original: body,
            },
            _ => IcmpMessage::Other {
                kind,
                code,
                rest: [buf[4], buf[5], buf[6], buf[7]],
                data: body,
            },
        })
    }

    /// Whether a whole ICMP message carries a correct checksum.
    pub fn checksum_valid(buf: &[u8]) -> bool {
        buf.len() >= HEADER_LEN && internet_checksum(buf) == 0
    }

    /// Append the message with its checksum computed.
    pub fn write(&self, out: &mut Vec<u8>) {
        let start = out.len();
        let (kind, code, rest, data): (u8, u8, [u8; 4], &[u8]) = match *self {
            IcmpMessage::EchoRequest { id, seq, data } => {
                (TYPE_ECHO_REQUEST, 0, join(id, seq), data)
            }
            IcmpMessage::EchoReply { id, seq, data } => (TYPE_ECHO_REPLY, 0, join(id, seq), data),
            IcmpMessage::DestUnreachable { code, original } => {
                (TYPE_DEST_UNREACHABLE, code, [0; 4], original)
            }
            IcmpMessage::TimeExceeded { code, original } => {
                (TYPE_TIME_EXCEEDED, code, [0; 4], original)
            }
            IcmpMessage::Other {
                kind,
                code,
                rest,
                data,
            } => (kind, code, rest, data),
        };
        out.extend_from_slice(&[kind, code, 0, 0]);
        out.extend_from_slice(&rest);
        out.extend_from_slice(data);
        let c = internet_checksum(&out[start..]);
        out[start + 2..start + 4].copy_from_slice(&c.to_be_bytes());
    }
}

fn join(id: u16, seq: u16) -> [u8; 4] {
    let (i, s) = (id.to_be_bytes(), seq.to_be_bytes());
    [i[0], i[1], s[0], s[1]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::{Ipv4Header, PROTO_UDP};
    use crate::udp::UdpHeader;
    use std::net::Ipv4Addr;

    #[test]
    fn echo_request_bytes() {
        let mut buf = Vec::new();
        IcmpMessage::EchoRequest {
            id: 0x0102,
            seq: 0x0304,
            data: b"",
        }
        .write(&mut buf);
        // Checksum of 0800 0000 0102 0304: !(0x0800 + 0x0102 + 0x0304).
        let c: u16 = !(0x0800u16 + 0x0102 + 0x0304);
        let c = c.to_be_bytes();
        assert_eq!(buf, [8, 0, c[0], c[1], 1, 2, 3, 4]);
        assert!(IcmpMessage::checksum_valid(&buf));
    }

    #[test]
    fn round_trips() {
        for msg in [
            IcmpMessage::EchoReply {
                id: 7,
                seq: 9,
                data: b"ping",
            },
            IcmpMessage::DestUnreachable {
                code: 13,
                original: b"0123456789abcdefghijklmnopqrstuvwxyz",
            },
            IcmpMessage::TimeExceeded {
                code: 0,
                original: b"x",
            },
            IcmpMessage::Other {
                kind: 13,
                code: 0,
                rest: [1, 2, 3, 4],
                data: b"",
            },
        ] {
            let mut buf = Vec::new();
            msg.write(&mut buf);
            assert!(IcmpMessage::checksum_valid(&buf));
            assert_eq!(IcmpMessage::parse(&buf).unwrap(), msg);
        }
    }

    #[test]
    fn port_unreachable_quotes_the_probe() {
        let (us, them) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let mut probe = Vec::new();
        Ipv4Header::new(us, them, PROTO_UDP, 64, 1).write(8, &mut probe);
        UdpHeader::new(40000, 161).write(us, them, &[], &mut probe);
        let mut buf = Vec::new();
        IcmpMessage::DestUnreachable {
            code: CODE_PORT_UNREACHABLE,
            original: &probe,
        }
        .write(&mut buf);
        let IcmpMessage::DestUnreachable { code, original } = IcmpMessage::parse(&buf).unwrap()
        else {
            panic!("wrong type");
        };
        assert_eq!(code, CODE_PORT_UNREACHABLE);
        let (ip, inner) = Ipv4Header::parse(original).unwrap();
        assert_eq!((ip.src, ip.dst), (us, them));
        assert_eq!(UdpHeader::parse_ports(inner).unwrap(), (40000, 161));
    }

    #[test]
    fn short_messages_are_errors() {
        assert!(IcmpMessage::parse(&[8, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(!IcmpMessage::checksum_valid(&[0xff; 4]));
    }
}
