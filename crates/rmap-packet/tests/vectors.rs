//! Known byte vectors and randomized robustness tests.
//!
//! Every parser here sees bytes straight off the network, so it must turn
//! garbage into an error and never panic.

use std::net::Ipv4Addr;

use rmap_packet::ipv4::{PROTO_TCP, PROTO_UDP};
use rmap_packet::{
    ArpPacket, EthernetHeader, IcmpMessage, Ipv4Header, MacAddr, TcpFlags, TcpHeader, TcpOption,
    UdpHeader, internet_checksum,
};

/// A SYN from 192.168.0.2:12345 to 192.168.0.1:80, seq 0x01020304,
/// window 1024, MSS 1460, DF, TTL 64, IP ID 1.
///
/// Checksums worked by hand. IP: the header words
/// 4500+002c+0001+4000+4006+c0a8+0002+c0a8+0001 sum to 0x24686, which folds
/// to 0x4688 and complements to 0xb977. TCP: 0xde43, checked against an
/// independent implementation.
#[rustfmt::skip]
const KNOWN_SYN: [u8; 44] = [
    0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0xb9, 0x77,
    0xc0, 0xa8, 0x00, 0x02, 0xc0, 0xa8, 0x00, 0x01,
    0x30, 0x39, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x60, 0x02, 0x04, 0x00, 0xde, 0x43, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
];

const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 2);
const DST: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);

#[test]
fn builds_the_known_syn() {
    let tcp = TcpHeader {
        src_port: 12345,
        dst_port: 80,
        seq: 0x0102_0304,
        flags: TcpFlags::SYN,
        window: 1024,
        options: vec![TcpOption::Mss(1460)],
        ..TcpHeader::default()
    };
    let mut buf = Vec::new();
    Ipv4Header::new(SRC, DST, PROTO_TCP, 64, 1).write(tcp.header_len(), &mut buf);
    tcp.write(SRC, DST, &[], &mut buf);
    assert_eq!(buf, KNOWN_SYN);
}

#[test]
fn parses_the_known_syn() {
    assert!(Ipv4Header::checksum_valid(&KNOWN_SYN));
    let (ip, segment) = Ipv4Header::parse(&KNOWN_SYN).unwrap();
    assert_eq!(
        (ip.src, ip.dst, ip.protocol, ip.ttl),
        (SRC, DST, PROTO_TCP, 64)
    );
    assert_eq!(ip.checksum, 0xb977);
    assert!(TcpHeader::checksum_valid(ip.src, ip.dst, segment));
    let (tcp, payload) = TcpHeader::parse(segment).unwrap();
    assert!(payload.is_empty());
    assert_eq!((tcp.src_port, tcp.dst_port), (12345, 80));
    assert_eq!(tcp.seq, 0x0102_0304);
    assert_eq!(tcp.flags, TcpFlags::SYN);
    assert_eq!(tcp.checksum, 0xde43);
    assert_eq!(tcp.options, vec![TcpOption::Mss(1460)]);
}

#[test]
fn corruption_breaks_checksums() {
    for i in 0..KNOWN_SYN.len() {
        let mut bad = KNOWN_SYN;
        bad[i] ^= 0x10;
        let ip_ok = Ipv4Header::checksum_valid(&bad);
        let tcp_ok = match Ipv4Header::parse(&bad) {
            Ok((ip, seg)) => TcpHeader::checksum_valid(ip.src, ip.dst, seg),
            Err(_) => false,
        };
        assert!(!(ip_ok && tcp_ok), "flipping byte {i} went unnoticed");
    }
}

#[test]
fn full_frame_round_trip() {
    let mut frame = Vec::new();
    EthernetHeader {
        dst: MacAddr::BROADCAST,
        src: MacAddr([2, 0, 0, 0, 0, 9]),
        ethertype: rmap_packet::ethernet::ETHERTYPE_IPV4,
    }
    .write(&mut frame);
    let mut udp = Vec::new();
    UdpHeader::new(40000, 53).write(SRC, DST, b"dns?", &mut udp);
    Ipv4Header::new(SRC, DST, PROTO_UDP, 64, 7).write(udp.len(), &mut frame);
    frame.extend_from_slice(&udp);

    let (eth, packet) = EthernetHeader::parse(&frame).unwrap();
    assert_eq!(eth.dst, MacAddr::BROADCAST);
    let (ip, datagram) = Ipv4Header::parse(packet).unwrap();
    assert!(UdpHeader::checksum_valid(ip.src, ip.dst, datagram));
    let (h, payload) = UdpHeader::parse(datagram).unwrap();
    assert_eq!((h.src_port, h.dst_port, payload), (40000, 53, &b"dns?"[..]));
}

// ---------------------------------------------------------- randomised ---

/// Small deterministic PRNG so failures reproduce from the printed seed.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

/// Valid packets of every kind, to mutate into near-misses.
fn seeds() -> Vec<Vec<u8>> {
    let mut out = vec![KNOWN_SYN.to_vec()];
    let mut syn = Vec::new();
    let tcp = TcpHeader::syn(1, 2, 3);
    Ipv4Header::new(SRC, DST, PROTO_TCP, 64, 1).write(tcp.header_len(), &mut syn);
    tcp.write(SRC, DST, &[], &mut syn);
    out.push(syn);
    let mut arp = Vec::new();
    ArpPacket::request(MacAddr::ZERO, SRC, DST).write(&mut arp);
    out.push(arp);
    let mut icmp = Vec::new();
    IcmpMessage::DestUnreachable {
        code: 3,
        original: &KNOWN_SYN[..28],
    }
    .write(&mut icmp);
    out.push(icmp);
    out
}

/// Run every parser over `buf`, following nested headers where they parse.
fn parse_everything(buf: &[u8]) {
    let _ = EthernetHeader::parse(buf);
    let _ = ArpPacket::parse(buf);
    let _ = Ipv4Header::checksum_valid(buf);
    let _ = IcmpMessage::checksum_valid(buf);
    let _ = TcpOption::parse_all(buf);
    let _ = TcpHeader::parse_prefix(buf);
    let _ = UdpHeader::parse_ports(buf);
    let _ = UdpHeader::parse(buf);
    let _ = internet_checksum(buf);
    if let Ok((tcp, _)) = TcpHeader::parse(buf) {
        let _ = tcp.header_len();
    }
    if let Ok(IcmpMessage::DestUnreachable { original, .. }) = IcmpMessage::parse(buf) {
        parse_everything(original);
    }
    if let Ok((ip, payload)) = Ipv4Header::parse(buf) {
        let _ = TcpHeader::checksum_valid(ip.src, ip.dst, payload);
        let _ = UdpHeader::checksum_valid(ip.src, ip.dst, payload);
        let _ = TcpHeader::parse(payload);
        let _ = UdpHeader::parse(payload);
        let _ = IcmpMessage::parse(payload);
        // Re-encoding whatever parsed must not panic either.
        let mut out = Vec::new();
        ip.write(payload.len(), &mut out);
    }
}

fn check(seed: u64, i: usize, input: &[u8]) {
    let owned = input.to_vec();
    let result = std::panic::catch_unwind(|| parse_everything(&owned));
    assert!(
        result.is_ok(),
        "seed {seed:#x} iteration {i}: input {input:02x?} panicked"
    );
}

#[test]
fn random_bytes_never_panic() {
    let seed = 0x9ac4_e75e_ed01;
    let mut rng = XorShift(seed);
    for i in 0..100_000 {
        let len = (rng.next() % 96) as usize;
        let input: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        check(seed, i, &input);
    }
}

#[test]
fn mutated_packets_never_panic() {
    let seed = 0x0bad_c0de_5eed;
    let mut rng = XorShift(seed);
    let seeds = seeds();
    for i in 0..100_000 {
        let mut input = seeds[(rng.next() % seeds.len() as u64) as usize].clone();
        for _ in 0..=(rng.next() % 4) {
            match rng.next() % 4 {
                0 if !input.is_empty() => {
                    let at = (rng.next() % input.len() as u64) as usize;
                    input[at] = rng.byte();
                }
                1 => input.truncate((rng.next() % (input.len() as u64 + 1)) as usize),
                2 => input.push(rng.byte()),
                _ if !input.is_empty() => {
                    // Header-length and length fields are where parsers slip.
                    let at = [0usize, 2, 3, 4, 5, 12][(rng.next() % 6) as usize];
                    if at < input.len() {
                        input[at] = rng.byte();
                    }
                }
                _ => {}
            }
        }
        check(seed, i, &input);
    }
}

#[test]
fn every_prefix_of_valid_packets_is_safe() {
    for packet in seeds() {
        for end in 0..=packet.len() {
            check(0, end, &packet[..end]);
        }
    }
}
