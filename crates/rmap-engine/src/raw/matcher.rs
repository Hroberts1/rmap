//! Building probe packets and matching replies to them, without state.
//!
//! A SYN's sequence number is a keyed hash of (target address, target port,
//! source port), with a random key per scan. A genuine SYN-ACK or RST must
//! acknowledge that number plus one, and an ICMP error must quote it, so
//! replies are recognised without remembering what was sent, and stray or
//! spoofed traffic is ignored. ICMP echo uses a per-scan identifier, and UDP
//! probes come from one per-scan source port.
//!
//! IPv4 replies arrive with their IP header. IPv6 raw sockets never pass
//! the IPv6 header up, so the IPv6 matchers take the sender's address (from
//! `recvfrom`) and the TCP segment or ICMPv6 message separately.
//!
//! None of this touches sockets, so it is tested on every platform.

use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rmap_core::{PortState, Protocol};
use rmap_packet::arp::OP_REPLY;
use rmap_packet::ethernet::{ETHERTYPE_ARP, EthernetHeader};
use rmap_packet::ipv4::{PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use rmap_packet::ipv6::NEXT_ICMPV6;
use rmap_packet::{
    ArpPacket, IcmpMessage, Icmpv6Message, Ipv4Header, Ipv6Header, MacAddr, TcpFlags, TcpHeader,
    UdpHeader,
};

/// TTL for every probe we send.
const TTL: u8 = 64;

/// Payload of our echo requests, so they are recognisable in a capture.
const ECHO_DATA: &[u8] = b"rmap-ping";

/// What a target said about a port probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    SynAck,
    Rst,
    /// A UDP datagram came back from the port.
    Data,
    /// ICMP destination unreachable with this code.
    Unreachable(u8),
    /// ICMPv6 destination unreachable with this code. Its codes differ
    /// from ICMPv4's: port unreachable is 4.
    Unreachable6(u8),
}

/// Where raw probes to one host go from and to. Both ends are always the
/// same address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

impl Route {
    pub fn src(&self) -> IpAddr {
        match *self {
            Route::V4(src, _) => src.into(),
            Route::V6(src, _) => src.into(),
        }
    }

    pub fn dst(&self) -> IpAddr {
        match *self {
            Route::V4(_, dst) => dst.into(),
            Route::V6(_, dst) => dst.into(),
        }
    }
}

/// A reply matched to one of our probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matched {
    Port {
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
        reply: Reply,
    },
    /// An echo reply (or an ARP reply with an unusable sender address)
    /// from a host we pinged.
    HostUp(IpAddr),
    /// An ARP reply: the host is up and this is its hardware address.
    ArpReply { ip: Ipv4Addr, mac: MacAddr },
}

/// Port state for a TCP SYN probe's reply.
pub fn tcp_state(reply: Reply) -> PortState {
    match reply {
        Reply::SynAck => PortState::Open,
        Reply::Rst => PortState::Closed,
        // UDP data can't answer a SYN; treat it like any other oddity.
        Reply::Data | Reply::Unreachable(_) | Reply::Unreachable6(_) => PortState::Filtered,
    }
}

/// Port state for a UDP probe's reply.
pub fn udp_state(reply: Reply) -> PortState {
    match reply {
        Reply::Data => PortState::Open,
        Reply::Unreachable(rmap_packet::icmp::CODE_PORT_UNREACHABLE) => PortState::Closed,
        Reply::Unreachable6(rmap_packet::icmpv6::CODE_PORT_UNREACHABLE) => PortState::Closed,
        Reply::Unreachable(_) | Reply::Unreachable6(_) => PortState::Filtered,
        // A SYN-ACK or RST can't answer a UDP probe.
        Reply::SynAck | Reply::Rst => PortState::Filtered,
    }
}

/// Per-scan secrets for building probes and recognising replies.
pub struct Matcher {
    key: RandomState,
    src_port_base: u16,
    icmp_id: u16,
    /// Source port of UDP probes, or 0 if this scan sends none.
    udp_port: u16,
}

impl Matcher {
    pub fn new(udp_port: u16) -> Self {
        let key = RandomState::new();
        let h = key.hash_one(0x726d_6170_u64);
        Matcher {
            src_port_base: 40_000 + (h % 20_000) as u16,
            icmp_id: (h >> 32) as u16,
            udp_port,
            key,
        }
    }

    pub fn icmp_id(&self) -> u16 {
        self.icmp_id
    }

    /// The keyed hash used as a SYN's sequence number.
    pub fn cookie(&self, ip: impl Into<IpAddr>, dst_port: u16, src_port: u16) -> u32 {
        self.key.hash_one((ip.into(), dst_port, src_port)) as u32
    }

    /// Source port for a SYN. Each retry uses a new one, so a late answer
    /// to an earlier try still matches.
    pub fn src_port(&self, try_no: u8) -> u16 {
        self.src_port_base.wrapping_add(u16::from(try_no))
    }

    /// A complete SYN packet, IP header included.
    pub fn syn_packet(&self, route: Route, port: u16, try_no: u8) -> Vec<u8> {
        let sport = self.src_port(try_no);
        let seq = self.cookie(route.dst(), port, sport);
        let tcp = TcpHeader::syn(sport, port, seq);
        let mut buf = Vec::with_capacity(80);
        match route {
            Route::V4(src, dst) => {
                Ipv4Header::new(src, dst, PROTO_TCP, TTL, seq as u16)
                    .write(tcp.header_len(), &mut buf);
                tcp.write(src, dst, &[], &mut buf);
            }
            Route::V6(src, dst) => {
                Ipv6Header::new(src, dst, PROTO_TCP, TTL).write(tcp.header_len(), &mut buf);
                tcp.write_v6(src, dst, &[], &mut buf);
            }
        }
        buf
    }

    /// A complete UDP packet from the scan's UDP source port.
    pub fn udp_packet(&self, route: Route, port: u16, payload: &[u8]) -> Vec<u8> {
        let udp = UdpHeader::new(self.udp_port, port);
        let mut buf = Vec::with_capacity(48 + payload.len());
        match route {
            Route::V4(src, dst) => {
                let id = self.cookie(dst, port, self.udp_port) as u16;
                Ipv4Header::new(src, dst, PROTO_UDP, TTL, id).write(8 + payload.len(), &mut buf);
                udp.write(src, dst, payload, &mut buf);
            }
            Route::V6(src, dst) => {
                Ipv6Header::new(src, dst, PROTO_UDP, TTL).write(8 + payload.len(), &mut buf);
                udp.write_v6(src, dst, payload, &mut buf);
            }
        }
        buf
    }

    /// A complete ICMP (or ICMPv6) echo request.
    pub fn echo_packet(&self, route: Route, seq: u16) -> Vec<u8> {
        let (id, data) = (self.icmp_id, ECHO_DATA);
        let mut icmp = Vec::with_capacity(8 + ECHO_DATA.len());
        let mut buf = Vec::with_capacity(48 + ECHO_DATA.len());
        match route {
            Route::V4(src, dst) => {
                IcmpMessage::EchoRequest { id, seq, data }.write(&mut icmp);
                Ipv4Header::new(src, dst, PROTO_ICMP, TTL, seq).write(icmp.len(), &mut buf);
            }
            Route::V6(src, dst) => {
                Icmpv6Message::EchoRequest { id, seq, data }.write(src, dst, &mut icmp);
                Ipv6Header::new(src, dst, NEXT_ICMPV6, TTL).write(icmp.len(), &mut buf);
            }
        }
        buf.extend_from_slice(&icmp);
        buf
    }

    /// A broadcast Ethernet frame asking who has `dst`.
    pub fn arp_frame(mac: MacAddr, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut buf = Vec::with_capacity(42);
        EthernetHeader {
            dst: MacAddr::BROADCAST,
            src: mac,
            ethertype: ETHERTYPE_ARP,
        }
        .write(&mut buf);
        ArpPacket::request(mac, src, dst).write(&mut buf);
        buf
    }

    /// Match a TCP packet (IP header included) from a raw TCP socket.
    pub fn match_tcp(&self, packet: &[u8]) -> Option<Matched> {
        let (ip, segment) = Ipv4Header::parse(packet).ok()?;
        if ip.protocol != PROTO_TCP || ip.is_later_fragment() {
            return None;
        }
        self.tcp_reply(ip.src.into(), segment)
    }

    /// Match a TCP segment from `src`, read from a raw IPv6 TCP socket.
    pub fn match_tcp6(&self, src: Ipv6Addr, segment: &[u8]) -> Option<Matched> {
        self.tcp_reply(src.into(), segment)
    }

    fn tcp_reply(&self, src: IpAddr, segment: &[u8]) -> Option<Matched> {
        let (tcp, _) = TcpHeader::parse(segment).ok()?;
        // Checksums aren't checked: loopback traffic often carries partial
        // ones. The cookie is a stronger test anyway.
        if tcp.ack.wrapping_sub(1) != self.cookie(src, tcp.src_port, tcp.dst_port) {
            return None;
        }
        let reply = if tcp.flags.contains(TcpFlags::SYN | TcpFlags::ACK) {
            Reply::SynAck
        } else if tcp.flags.contains(TcpFlags::RST) {
            Reply::Rst
        } else {
            return None;
        };
        Some(Matched::Port {
            ip: src,
            port: tcp.src_port,
            protocol: Protocol::Tcp,
            reply,
        })
    }

    /// Match an ICMP packet (IP header included) from a raw ICMP socket.
    pub fn match_icmp(&self, packet: &[u8]) -> Option<Matched> {
        let (ip, body) = Ipv4Header::parse(packet).ok()?;
        if ip.protocol != PROTO_ICMP || ip.is_later_fragment() {
            return None;
        }
        match IcmpMessage::parse(body).ok()? {
            IcmpMessage::EchoReply { id, .. } if id == self.icmp_id => {
                Some(Matched::HostUp(ip.src.into()))
            }
            IcmpMessage::DestUnreachable { code, original } => {
                let (quoted, inner) = Ipv4Header::parse(original).ok()?;
                let reply = Reply::Unreachable(code);
                self.quoted_probe(quoted.dst.into(), quoted.protocol, inner, reply)
            }
            _ => None,
        }
    }

    /// Match an ICMPv6 message from `src`, read from a raw ICMPv6 socket.
    pub fn match_icmp6(&self, src: Ipv6Addr, message: &[u8]) -> Option<Matched> {
        match Icmpv6Message::parse(message).ok()? {
            Icmpv6Message::EchoReply { id, .. } if id == self.icmp_id => {
                Some(Matched::HostUp(src.into()))
            }
            Icmpv6Message::DestUnreachable { code, original } => {
                let (quoted, inner) = Ipv6Header::parse(original).ok()?;
                let reply = Reply::Unreachable6(code);
                self.quoted_probe(quoted.dst.into(), quoted.next_header, inner, reply)
            }
            _ => None,
        }
    }

    /// Match the probe quoted in an ICMP error: `dst` and `protocol` from
    /// the quoted IP header, `inner` the start of its TCP or UDP header.
    fn quoted_probe(
        &self,
        dst: IpAddr,
        protocol: u8,
        inner: &[u8],
        reply: Reply,
    ) -> Option<Matched> {
        let (port, protocol) = match protocol {
            PROTO_TCP => {
                let (sport, dport, seq) = TcpHeader::parse_prefix(inner).ok()?;
                (seq == self.cookie(dst, dport, sport)).then_some((dport, Protocol::Tcp))?
            }
            PROTO_UDP => {
                let (sport, dport) = UdpHeader::parse_ports(inner).ok()?;
                (self.udp_port != 0 && sport == self.udp_port).then_some((dport, Protocol::Udp))?
            }
            _ => return None,
        };
        Some(Matched::Port {
            ip: dst,
            port,
            protocol,
            reply,
        })
    }

    /// Match an Ethernet frame from an ARP packet socket.
    pub fn match_arp(frame: &[u8]) -> Option<Matched> {
        let (eth, payload) = EthernetHeader::parse(frame).ok()?;
        if eth.ethertype != ETHERTYPE_ARP {
            return None;
        }
        let arp = ArpPacket::parse(payload).ok()?;
        if arp.op != OP_REPLY {
            return None;
        }
        let mac = arp.sender_mac;
        // A group or all-zero sender is junk; the host still answered.
        Some(if mac.0[0] & 0x01 != 0 || mac == MacAddr::ZERO {
            Matched::HostUp(arp.sender_ip.into())
        } else {
            Matched::ArpReply {
                ip: arp.sender_ip,
                mac,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmap_packet::icmp::CODE_PORT_UNREACHABLE;

    const US: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const THEM: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const R4: Route = Route::V4(US, THEM);
    const US6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const THEM6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    const R6: Route = Route::V6(US6, THEM6);

    /// The target's answer to `syn`, with the given flags and ack offset.
    fn answer(syn: &[u8], flags: TcpFlags, ack_delta: u32) -> Vec<u8> {
        let (ip, seg) = Ipv4Header::parse(syn).unwrap();
        let (tcp, _) = TcpHeader::parse(seg).unwrap();
        let reply = TcpHeader {
            src_port: tcp.dst_port,
            dst_port: tcp.src_port,
            seq: 777,
            ack: tcp.seq.wrapping_add(ack_delta),
            flags,
            window: 65535,
            ..TcpHeader::default()
        };
        let mut buf = Vec::new();
        Ipv4Header::new(ip.dst, ip.src, PROTO_TCP, 64, 0).write(reply.header_len(), &mut buf);
        reply.write(ip.dst, ip.src, &[], &mut buf);
        buf
    }

    fn unreachable(code: u8, quoted: &[u8], from: Ipv4Addr) -> Vec<u8> {
        let mut icmp = Vec::new();
        IcmpMessage::DestUnreachable {
            code,
            original: &quoted[..28.min(quoted.len())],
        }
        .write(&mut icmp);
        let mut buf = Vec::new();
        Ipv4Header::new(from, US, PROTO_ICMP, 64, 0).write(icmp.len(), &mut buf);
        buf.extend_from_slice(&icmp);
        buf
    }

    fn port(reply: Reply, protocol: Protocol, port: u16) -> Option<Matched> {
        Some(Matched::Port {
            ip: THEM.into(),
            port,
            protocol,
            reply,
        })
    }

    /// The target's answer to an IPv6 `syn`: just the TCP segment, as a raw
    /// IPv6 socket hands it over.
    fn answer6(syn: &[u8], flags: TcpFlags, ack_delta: u32) -> Vec<u8> {
        let (ip, seg) = Ipv6Header::parse(syn).unwrap();
        let (tcp, _) = TcpHeader::parse(seg).unwrap();
        let reply = TcpHeader {
            src_port: tcp.dst_port,
            dst_port: tcp.src_port,
            ack: tcp.seq.wrapping_add(ack_delta),
            flags,
            ..TcpHeader::default()
        };
        let mut buf = Vec::new();
        reply.write_v6(ip.dst, ip.src, &[], &mut buf);
        buf
    }

    /// An ICMPv6 destination unreachable quoting `probe`, as a raw ICMPv6
    /// socket hands it over.
    fn unreachable6(code: u8, probe: &[u8], from: Ipv6Addr) -> Vec<u8> {
        let mut buf = Vec::new();
        Icmpv6Message::DestUnreachable {
            code,
            original: probe,
        }
        .write(from, US6, &mut buf);
        buf
    }

    fn port6(reply: Reply, protocol: Protocol, port: u16) -> Option<Matched> {
        Some(Matched::Port {
            ip: THEM6.into(),
            port,
            protocol,
            reply,
        })
    }

    #[test]
    fn v6_syn_carries_the_cookie() {
        let m = Matcher::new(0);
        let syn = m.syn_packet(R6, 443, 2);
        let (ip, seg) = Ipv6Header::parse(&syn).unwrap();
        assert_eq!((ip.src, ip.dst, ip.next_header), (US6, THEM6, PROTO_TCP));
        assert_eq!(usize::from(ip.payload_len), seg.len());
        assert!(TcpHeader::checksum_valid_v6(US6, THEM6, seg));
        let (tcp, _) = TcpHeader::parse(seg).unwrap();
        assert_eq!(tcp.src_port, m.src_port(2));
        assert_eq!(tcp.seq, m.cookie(THEM6, 443, m.src_port(2)));
        assert_eq!(R6.src(), IpAddr::V6(US6));
        assert_eq!(R6.dst(), IpAddr::V6(THEM6));
    }

    #[test]
    fn v6_matches_syn_ack_and_rst() {
        let m = Matcher::new(0);
        let syn = m.syn_packet(R6, 22, 0);
        let syn_ack = answer6(&syn, TcpFlags::SYN | TcpFlags::ACK, 1);
        assert_eq!(
            m.match_tcp6(THEM6, &syn_ack),
            port6(Reply::SynAck, Protocol::Tcp, 22)
        );
        assert_eq!(
            m.match_tcp6(THEM6, &answer6(&syn, TcpFlags::RST | TcpFlags::ACK, 1)),
            port6(Reply::Rst, Protocol::Tcp, 22)
        );
        // The cookie is keyed by address: the same answer from elsewhere,
        // or with the wrong ack, doesn't match.
        assert_eq!(m.match_tcp6(US6, &syn_ack), None);
        let wrong = answer6(&syn, TcpFlags::SYN | TcpFlags::ACK, 2);
        assert_eq!(m.match_tcp6(THEM6, &wrong), None);
        // An IPv4 address with the same cookie input isn't the same host.
        let r4 = Matcher::new(0);
        assert_ne!(r4.cookie(THEM, 22, 1), r4.cookie(THEM6, 22, 1));
        assert_eq!(m.match_tcp6(THEM6, &[]), None);
    }

    #[test]
    fn v6_unreachable_for_a_syn_and_for_udp() {
        let m = Matcher::new(45_000);
        let router = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfe);
        let syn = m.syn_packet(R6, 8080, 0);
        let admin = m.match_icmp6(router, &unreachable6(1, &syn, router));
        assert_eq!(admin, port6(Reply::Unreachable6(1), Protocol::Tcp, 8080));
        let forged = Matcher::new(45_000).syn_packet(R6, 8080, 0);
        assert_eq!(
            m.match_icmp6(router, &unreachable6(1, &forged, router)),
            None
        );

        let probe = m.udp_packet(R6, 161, b"x");
        let (ip, seg) = Ipv6Header::parse(&probe).unwrap();
        assert_eq!(ip.next_header, PROTO_UDP);
        assert!(UdpHeader::checksum_valid_v6(US6, THEM6, seg));
        let closed = m.match_icmp6(THEM6, &unreachable6(4, &probe, THEM6));
        assert_eq!(closed, port6(Reply::Unreachable6(4), Protocol::Udp, 161));
        // A clipped quote that still holds the UDP ports is enough.
        let clipped = m.match_icmp6(THEM6, &unreachable6(4, &probe[..44], THEM6));
        assert_eq!(clipped, closed);
        assert_eq!(
            m.match_icmp6(THEM6, &unreachable6(4, &probe[..43], THEM6)),
            None
        );
        let theirs = Matcher::new(45_001).udp_packet(R6, 161, b"x");
        assert_eq!(m.match_icmp6(THEM6, &unreachable6(4, &theirs, THEM6)), None);
        // An IPv4 packet quoted in an ICMPv6 error is nonsense.
        let v4 = m.udp_packet(R4, 161, b"x");
        assert_eq!(m.match_icmp6(THEM6, &unreachable6(4, &v4, THEM6)), None);
    }

    #[test]
    fn v6_echo_replies_need_our_id() {
        let m = Matcher::new(0);
        let request = m.echo_packet(R6, 3);
        let (ip, body) = Ipv6Header::parse(&request).unwrap();
        assert_eq!(ip.next_header, NEXT_ICMPV6);
        assert!(Icmpv6Message::checksum_valid(US6, THEM6, body));
        let reply_from = |id: u16| {
            let mut buf = Vec::new();
            Icmpv6Message::EchoReply {
                id,
                seq: 3,
                data: ECHO_DATA,
            }
            .write(THEM6, US6, &mut buf);
            buf
        };
        assert_eq!(
            m.match_icmp6(THEM6, &reply_from(m.icmp_id())),
            Some(Matched::HostUp(THEM6.into()))
        );
        assert_eq!(m.match_icmp6(THEM6, &reply_from(m.icmp_id() ^ 1)), None);
        assert_eq!(m.match_icmp6(US6, body), None, "our own request");
    }

    #[test]
    fn syn_carries_the_cookie() {
        let m = Matcher::new(0);
        let syn = m.syn_packet(R4, 443, 1);
        assert!(Ipv4Header::checksum_valid(&syn));
        let (ip, seg) = Ipv4Header::parse(&syn).unwrap();
        assert_eq!((ip.src, ip.dst, ip.protocol), (US, THEM, PROTO_TCP));
        assert!(TcpHeader::checksum_valid(US, THEM, seg));
        let (tcp, _) = TcpHeader::parse(seg).unwrap();
        assert_eq!(tcp.src_port, m.src_port(1));
        assert_eq!(tcp.seq, m.cookie(THEM, 443, m.src_port(1)));
        assert_eq!(tcp.flags, TcpFlags::SYN);
    }

    #[test]
    fn matches_syn_ack_and_rst() {
        let m = Matcher::new(0);
        let syn = m.syn_packet(R4, 22, 0);
        assert_eq!(
            m.match_tcp(&answer(&syn, TcpFlags::SYN | TcpFlags::ACK, 1)),
            port(Reply::SynAck, Protocol::Tcp, 22)
        );
        assert_eq!(
            m.match_tcp(&answer(&syn, TcpFlags::RST | TcpFlags::ACK, 1)),
            port(Reply::Rst, Protocol::Tcp, 22)
        );
    }

    #[test]
    fn ignores_replies_without_the_cookie() {
        let m = Matcher::new(0);
        let syn = m.syn_packet(R4, 22, 0);
        for delta in [0, 2, 0x8000_0000] {
            assert_eq!(
                m.match_tcp(&answer(&syn, TcpFlags::SYN | TcpFlags::ACK, delta)),
                None
            );
        }
        // Another scan's key doesn't validate.
        let other = Matcher::new(0);
        let syn = other.syn_packet(R4, 22, 0);
        assert_eq!(
            m.match_tcp(&answer(&syn, TcpFlags::SYN | TcpFlags::ACK, 1)),
            None
        );
        // Our own outgoing SYN, seen on loopback, is not a reply.
        assert_eq!(m.match_tcp(&m.syn_packet(R4, 22, 0)), None);
    }

    #[test]
    fn ignores_plain_acks_and_garbage() {
        let m = Matcher::new(0);
        let syn = m.syn_packet(R4, 22, 0);
        assert_eq!(m.match_tcp(&answer(&syn, TcpFlags::ACK, 1)), None);
        assert_eq!(m.match_tcp(&[]), None);
        assert_eq!(m.match_tcp(&[0x45; 40]), None);
        assert_eq!(m.match_icmp(&syn), None, "TCP is not ICMP");
    }

    #[test]
    fn icmp_unreachable_for_a_syn() {
        let m = Matcher::new(0);
        let syn = m.syn_packet(R4, 8080, 0);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        assert_eq!(
            m.match_icmp(&unreachable(13, &syn, router)),
            port(Reply::Unreachable(13), Protocol::Tcp, 8080)
        );
        let forged = Matcher::new(0).syn_packet(R4, 8080, 0);
        assert_eq!(m.match_icmp(&unreachable(13, &forged, router)), None);
    }

    #[test]
    fn icmp_unreachable_for_udp() {
        let m = Matcher::new(45_000);
        let probe = m.udp_packet(R4, 161, b"x");
        assert!(Ipv4Header::checksum_valid(&probe));
        assert_eq!(
            m.match_icmp(&unreachable(CODE_PORT_UNREACHABLE, &probe, THEM)),
            port(Reply::Unreachable(3), Protocol::Udp, 161)
        );
        // Someone else's UDP traffic.
        let theirs = Matcher::new(45_001).udp_packet(R4, 161, b"x");
        assert_eq!(m.match_icmp(&unreachable(3, &theirs, THEM)), None);
        // A scan with no UDP port accepts no UDP errors.
        let none = Matcher::new(0);
        let probe = none.udp_packet(R4, 161, b"");
        assert_eq!(none.match_icmp(&unreachable(3, &probe, THEM)), None);
    }

    #[test]
    fn echo_replies_need_our_id() {
        let m = Matcher::new(0);
        let request = m.echo_packet(R4, 3);
        let (_, body) = Ipv4Header::parse(&request).unwrap();
        assert!(IcmpMessage::checksum_valid(body));
        let reply_from = |id: u16| {
            let mut icmp = Vec::new();
            IcmpMessage::EchoReply {
                id,
                seq: 3,
                data: ECHO_DATA,
            }
            .write(&mut icmp);
            let mut buf = Vec::new();
            Ipv4Header::new(THEM, US, PROTO_ICMP, 64, 0).write(icmp.len(), &mut buf);
            buf.extend_from_slice(&icmp);
            buf
        };
        assert_eq!(
            m.match_icmp(&reply_from(m.icmp_id())),
            Some(Matched::HostUp(THEM.into()))
        );
        assert_eq!(m.match_icmp(&reply_from(m.icmp_id().wrapping_add(1))), None);
        assert_eq!(m.match_icmp(&request), None, "our own request");
    }

    #[test]
    fn arp_replies() {
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let request = Matcher::arp_frame(mac, US, THEM);
        assert_eq!(request.len(), 42);
        assert_eq!(
            Matcher::match_arp(&request),
            None,
            "requests aren't answers"
        );
        let mut reply = Vec::new();
        EthernetHeader {
            dst: mac,
            src: MacAddr([2, 0, 0, 0, 0, 2]),
            ethertype: ETHERTYPE_ARP,
        }
        .write(&mut reply);
        ArpPacket {
            op: OP_REPLY,
            sender_mac: MacAddr([2, 0, 0, 0, 0, 2]),
            sender_ip: THEM,
            target_mac: mac,
            target_ip: US,
        }
        .write(&mut reply);
        reply.extend_from_slice(&[0; 18]); // Ethernet minimum-size padding
        assert_eq!(
            Matcher::match_arp(&reply),
            Some(Matched::ArpReply {
                ip: THEM,
                mac: MacAddr([2, 0, 0, 0, 0, 2])
            })
        );
        assert_eq!(Matcher::match_arp(&reply[..20]), None);
        // A broadcast sender MAC still proves the host is up, but isn't kept.
        reply[22..28].copy_from_slice(&[0xff; 6]);
        assert_eq!(
            Matcher::match_arp(&reply),
            Some(Matched::HostUp(THEM.into()))
        );
    }

    #[test]
    fn state_mapping() {
        assert_eq!(tcp_state(Reply::SynAck), PortState::Open);
        assert_eq!(tcp_state(Reply::Rst), PortState::Closed);
        assert_eq!(tcp_state(Reply::Unreachable(1)), PortState::Filtered);
        assert_eq!(udp_state(Reply::Data), PortState::Open);
        assert_eq!(udp_state(Reply::Unreachable(3)), PortState::Closed);
        for code in [0, 1, 2, 9, 10, 13] {
            assert_eq!(udp_state(Reply::Unreachable(code)), PortState::Filtered);
        }
        assert_eq!(udp_state(Reply::Unreachable6(4)), PortState::Closed);
        for code in [0, 1, 2, 3, 5, 6] {
            assert_eq!(udp_state(Reply::Unreachable6(code)), PortState::Filtered);
        }
        assert_eq!(tcp_state(Reply::Unreachable6(4)), PortState::Filtered);
    }

    #[test]
    fn source_ports_stay_in_range() {
        for _ in 0..100 {
            let m = Matcher::new(0);
            assert!((40_000..60_000).contains(&m.src_port(0)));
            assert!(m.src_port(255) > m.src_port(0));
        }
    }

    #[test]
    fn random_packets_never_panic_the_matcher() {
        let m = Matcher::new(1234);
        let mut x: u64 = 0x5eed_1234_abcd;
        for i in 0..50_000 {
            let len = (i % 90) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let _ = m.match_tcp(&buf);
            let _ = m.match_icmp(&buf);
            let _ = m.match_tcp6(THEM6, &buf);
            let _ = m.match_icmp6(THEM6, &buf);
            let _ = Matcher::match_arp(&buf);
        }
    }
}
