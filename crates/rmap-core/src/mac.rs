//! Ethernet hardware addresses, as learned from ARP on the local network.

use std::fmt;
use std::str::FromStr;

use crate::{ParseError, err};

/// A 48-bit MAC address. Shown and stored as `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The first three bytes: the vendor prefix (OUI) when the address is
    /// globally unique.
    pub fn oui(self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Set by whoever assigned the address rather than burned in by the
    /// vendor: randomised (private Wi-Fi) addresses, most VMs and
    /// containers. The OUI then says nothing about the vendor.
    pub fn is_locally_administered(self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// A group address; never a real host's source address.
    pub fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = ParseError;

    /// Six two-digit hex groups separated by `:` or `-`, any case.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let sep = if s.contains('-') { '-' } else { ':' };
        let mut out = [0u8; 6];
        let mut groups = s.split(sep);
        for byte in &mut out {
            let g = groups.next().unwrap_or_default();
            if g.len() != 2 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
                return err(format!("invalid MAC address {s:?}"));
            }
            *byte = u8::from_str_radix(g, 16).expect("two hex digits");
        }
        if groups.next().is_some() {
            return err(format!("invalid MAC address {s:?}"));
        }
        Ok(MacAddr(out))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let m: MacAddr = "00:11:32:AB:cd:Ef".parse().unwrap();
        assert_eq!(m, MacAddr([0x00, 0x11, 0x32, 0xab, 0xcd, 0xef]));
        assert_eq!(m.to_string(), "00:11:32:ab:cd:ef");
        assert_eq!("00-11-32-ab-cd-ef".parse::<MacAddr>().unwrap(), m);
        assert_eq!(m.oui(), [0x00, 0x11, 0x32]);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            ":",
            "00:11:32:ab:cd",
            "00:11:32:ab:cd:ef:00",
            "00:11:32:ab:cd:e",
            "00:11:32:ab:cd:eff",
            "00:11:32-ab:cd:ef",
            "0g:11:32:ab:cd:ef",
            "+0:11:32:ab:cd:ef",
            "00:11:32:ab:cd:ef:",
            "001132abcdef",
            "é0:11:32:ab:cd:ef",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn address_kinds() {
        let m = |b0| MacAddr([b0, 0, 0, 0, 0, 1]);
        assert!(!m(0x00).is_locally_administered() && !m(0x00).is_multicast());
        assert!(m(0x02).is_locally_administered());
        assert!(m(0xda).is_locally_administered(), "randomised Wi-Fi style");
        assert!(m(0x01).is_multicast() && !m(0x01).is_locally_administered());
    }
}
