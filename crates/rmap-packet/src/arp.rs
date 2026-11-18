//! ARP for Ethernet and IPv4 (RFC 826).

use std::net::Ipv4Addr;

use crate::ethernet::{ETHERTYPE_IPV4, MacAddr};
use crate::{Error, Result, be16, need};

pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

/// Length of an Ethernet/IPv4 ARP packet.
pub const LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// "Who has `target_ip`? Tell `sender_ip`."
    pub fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpPacket {
            op: OP_REQUEST,
            sender_mac,
            sender_ip,
            target_mac: MacAddr::ZERO,
            target_ip,
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&1u16.to_be_bytes()); // hardware: Ethernet
        out.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        out.push(6);
        out.push(4);
        out.extend_from_slice(&self.op.to_be_bytes());
        out.extend_from_slice(&self.sender_mac.0);
        out.extend_from_slice(&self.sender_ip.octets());
        out.extend_from_slice(&self.target_mac.0);
        out.extend_from_slice(&self.target_ip.octets());
    }

    /// Parse an ARP packet. Only Ethernet/IPv4 ARP is accepted. Trailing
    /// bytes (Ethernet padding) are ignored.
    pub fn parse(buf: &[u8]) -> Result<ArpPacket> {
        need(buf, 8)?;
        if be16(buf, 0) != 1 || be16(buf, 2) != ETHERTYPE_IPV4 || buf[4] != 6 || buf[5] != 4 {
            return Err(Error::Invalid("ARP is not Ethernet/IPv4"));
        }
        need(buf, LEN)?;
        let mac = |at: usize| {
            let mut m = [0; 6];
            m.copy_from_slice(&buf[at..at + 6]);
            MacAddr(m)
        };
        let ip = |at: usize| Ipv4Addr::new(buf[at], buf[at + 1], buf[at + 2], buf[at + 3]);
        Ok(ArpPacket {
            op: be16(buf, 6),
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_bytes() {
        let p = ArpPacket::request(
            MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        let mut buf = Vec::new();
        p.write(&mut buf);
        #[rustfmt::skip]
        let expected = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 192, 168, 1, 10,
            0, 0, 0, 0, 0, 0, 192, 168, 1, 1,
        ];
        assert_eq!(buf, expected);
        assert_eq!(ArpPacket::parse(&buf).unwrap(), p);
    }

    #[test]
    fn rejects_other_hardware_and_truncation() {
        let mut buf = Vec::new();
        ArpPacket::request(MacAddr::ZERO, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST).write(&mut buf);
        assert!(matches!(
            ArpPacket::parse(&buf[..27]),
            Err(Error::Truncated { .. })
        ));
        buf[1] = 6; // IEEE 802 hardware type
        assert!(matches!(ArpPacket::parse(&buf), Err(Error::Invalid(_))));
    }
}
