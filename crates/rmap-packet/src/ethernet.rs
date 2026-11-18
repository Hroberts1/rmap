//! Ethernet II framing.

use crate::{Result, be16, need};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Length of an Ethernet II header (no VLAN tag).
pub const HEADER_LEN: usize = 14;

/// A 48-bit hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
}

impl EthernetHeader {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.dst.0);
        out.extend_from_slice(&self.src.0);
        out.extend_from_slice(&self.ethertype.to_be_bytes());
    }

    /// Parse a frame, returning the header and the payload after it.
    pub fn parse(buf: &[u8]) -> Result<(EthernetHeader, &[u8])> {
        need(buf, HEADER_LEN)?;
        let mac = |at: usize| {
            let mut m = [0; 6];
            m.copy_from_slice(&buf[at..at + 6]);
            MacAddr(m)
        };
        let header = EthernetHeader {
            dst: mac(0),
            src: mac(6),
            ethertype: be16(buf, 12),
        };
        Ok((header, &buf[HEADER_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let h = EthernetHeader {
            dst: MacAddr::BROADCAST,
            src: MacAddr([0x02, 0, 0, 0, 0, 1]),
            ethertype: ETHERTYPE_ARP,
        };
        let mut buf = Vec::new();
        h.write(&mut buf);
        buf.extend_from_slice(b"xy");
        assert_eq!(&buf[12..14], &[0x08, 0x06]);
        let (back, payload) = EthernetHeader::parse(&buf).unwrap();
        assert_eq!(back, h);
        assert_eq!(payload, b"xy");
        assert!(EthernetHeader::parse(&buf[..13]).is_err());
    }

    #[test]
    fn mac_display() {
        assert_eq!(
            MacAddr([0xde, 0xad, 0xbe, 0xef, 0x00, 0x0a]).to_string(),
            "de:ad:be:ef:00:0a"
        );
    }
}
