//! Hardware vendor from a MAC address.
//!
//! The table is small and hand-written: vendors common on small-business
//! and municipal networks, with only prefixes we are sure of. It is not the
//! IEEE registry (bundling that, or any third-party OUI file, needs a
//! licensing decision first), so an unknown prefix means "not in our
//! table", not "unregistered".
//!
//! Locally administered addresses (randomised Wi-Fi MACs, most VMs and
//! containers) carry no vendor prefix, so they are reported as such
//! instead of guessed.

use rmap_core::MacAddr;

/// What a MAC address says about the hardware behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Known(&'static str),
    /// Locally administered: the prefix is not a vendor's.
    Randomised,
    /// Globally unique, but not in our table.
    Unknown,
}

impl Vendor {
    /// The vendor's name, if known.
    pub fn name(self) -> Option<&'static str> {
        match self {
            Vendor::Known(name) => Some(name),
            _ => None,
        }
    }

    /// Short text for display: the vendor, "random MAC", or nothing.
    pub fn label(self) -> Option<&'static str> {
        match self {
            Vendor::Known(name) => Some(name),
            Vendor::Randomised => Some("random MAC"),
            Vendor::Unknown => None,
        }
    }
}

/// The vendor behind `mac`.
pub fn lookup(mac: MacAddr) -> Vendor {
    let oui = mac.oui();
    if let Some((_, name)) = LOCAL_CONVENTIONS.iter().find(|(p, _)| *p == oui) {
        return Vendor::Known(name);
    }
    if mac.is_locally_administered() || mac.is_multicast() {
        return Vendor::Randomised;
    }
    match OUIS.iter().find(|(p, _)| *p == oui) {
        Some((_, name)) => Vendor::Known(name),
        None => Vendor::Unknown,
    }
}

/// Locally administered prefixes that a hypervisor uses by default, so
/// they do identify the platform.
const LOCAL_CONVENTIONS: &[([u8; 3], &str)] = &[([0x52, 0x54, 0x00], "QEMU/KVM")];

/// Vendor prefixes. Grouped by vendor; names kept short for the host table.
// shortcut: linear search, fine per frame at this size; sort and binary
// search if the table grows into the thousands.
#[rustfmt::skip]
const OUIS: &[([u8; 3], &str)] = &[
    // Storage
    ([0x00, 0x11, 0x32], "Synology"),
    ([0x90, 0x09, 0xd0], "Synology"),
    ([0x00, 0x08, 0x9b], "QNAP"),
    ([0x24, 0x5e, 0xbe], "QNAP"),
    // Network
    ([0x00, 0x15, 0x6d], "Ubiquiti"),
    ([0x00, 0x27, 0x22], "Ubiquiti"),
    ([0x04, 0x18, 0xd6], "Ubiquiti"),
    ([0x18, 0xe8, 0x29], "Ubiquiti"),
    ([0x24, 0x5a, 0x4c], "Ubiquiti"),
    ([0x24, 0xa4, 0x3c], "Ubiquiti"),
    ([0x44, 0xd9, 0xe7], "Ubiquiti"),
    ([0x68, 0x72, 0x51], "Ubiquiti"),
    ([0x68, 0xd7, 0x9a], "Ubiquiti"),
    ([0x70, 0xa7, 0x41], "Ubiquiti"),
    ([0x74, 0x83, 0xc2], "Ubiquiti"),
    ([0x74, 0xac, 0xb9], "Ubiquiti"),
    ([0x78, 0x8a, 0x20], "Ubiquiti"),
    ([0x80, 0x2a, 0xa8], "Ubiquiti"),
    ([0xac, 0x8b, 0xa9], "Ubiquiti"),
    ([0xb4, 0xfb, 0xe4], "Ubiquiti"),
    ([0xd0, 0x21, 0xf9], "Ubiquiti"),
    ([0xe0, 0x63, 0xda], "Ubiquiti"),
    ([0xf0, 0x9f, 0xc2], "Ubiquiti"),
    ([0xfc, 0xec, 0xda], "Ubiquiti"),
    ([0x00, 0x00, 0x0c], "Cisco"),
    ([0x00, 0x40, 0x96], "Cisco"),
    ([0x00, 0x18, 0x0a], "Cisco Meraki"),
    ([0x0c, 0x8d, 0xdb], "Cisco Meraki"),
    ([0x88, 0x15, 0x44], "Cisco Meraki"),
    ([0xac, 0x17, 0xc8], "Cisco Meraki"),
    ([0xe0, 0x55, 0x3d], "Cisco Meraki"),
    ([0xe0, 0xcb, 0xbc], "Cisco Meraki"),
    ([0x00, 0x0b, 0x86], "Aruba"),
    ([0x00, 0x1a, 0x1e], "Aruba"),
    ([0x00, 0x24, 0x6c], "Aruba"),
    ([0x24, 0xde, 0xc6], "Aruba"),
    ([0x6c, 0xf3, 0x7f], "Aruba"),
    ([0x94, 0xb4, 0x0f], "Aruba"),
    ([0x9c, 0x1c, 0x12], "Aruba"),
    ([0xd8, 0xc7, 0xc8], "Aruba"),
    ([0x00, 0x09, 0x0f], "Fortinet"),
    ([0x08, 0x5b, 0x0e], "Fortinet"),
    ([0x70, 0x4c, 0xa5], "Fortinet"),
    ([0x90, 0x6c, 0xac], "Fortinet"),
    ([0xe8, 0x1c, 0xba], "Fortinet"),
    ([0x00, 0x06, 0xb1], "SonicWall"),
    ([0x00, 0x17, 0xc5], "SonicWall"),
    ([0x18, 0xb1, 0x69], "SonicWall"),
    ([0x2c, 0xb8, 0xed], "SonicWall"),
    ([0xc0, 0xea, 0xe4], "SonicWall"),
    // Computers and servers
    ([0x00, 0x0b, 0xcd], "HP"),
    ([0x00, 0x14, 0x38], "HP"),
    ([0x00, 0x17, 0xa4], "HP"),
    ([0x00, 0x1f, 0x29], "HP"),
    ([0x00, 0x21, 0x5a], "HP"),
    ([0x00, 0x23, 0x7d], "HP"),
    ([0x00, 0x25, 0xb3], "HP"),
    ([0x3c, 0xd9, 0x2b], "HP"),
    ([0x9c, 0x8e, 0x99], "HP"),
    ([0xa0, 0xd3, 0xc1], "HP"),
    ([0xb4, 0x99, 0xba], "HP"),
    ([0xd4, 0x85, 0x64], "HP"),
    ([0xec, 0xb1, 0xd7], "HP"),
    ([0x00, 0x06, 0x5b], "Dell"),
    ([0x00, 0x0b, 0xdb], "Dell"),
    ([0x00, 0x13, 0x72], "Dell"),
    ([0x00, 0x14, 0x22], "Dell"),
    ([0x00, 0x1e, 0xc9], "Dell"),
    ([0x00, 0x21, 0x9b], "Dell"),
    ([0x00, 0x24, 0xe8], "Dell"),
    ([0x00, 0x26, 0xb9], "Dell"),
    ([0x14, 0xfe, 0xb5], "Dell"),
    ([0x18, 0x03, 0x73], "Dell"),
    ([0x18, 0xa9, 0x9b], "Dell"),
    ([0xb0, 0x83, 0xfe], "Dell"),
    ([0xd4, 0xbe, 0xd9], "Dell"),
    ([0xf8, 0xb1, 0x56], "Dell"),
    ([0xf8, 0xbc, 0x12], "Dell"),
    ([0x00, 0x25, 0x90], "Supermicro"),
    ([0x0c, 0xc4, 0x7a], "Supermicro"),
    ([0xac, 0x1f, 0x6b], "Supermicro"),
    ([0x00, 0x03, 0x93], "Apple"),
    ([0x00, 0x0a, 0x95], "Apple"),
    ([0x00, 0x0d, 0x93], "Apple"),
    ([0x00, 0x1b, 0x63], "Apple"),
    ([0x00, 0x1e, 0xc2], "Apple"),
    ([0x00, 0x25, 0x00], "Apple"),
    ([0x00, 0x26, 0xbb], "Apple"),
    ([0x28, 0xcf, 0xe9], "Apple"),
    ([0x3c, 0x07, 0x54], "Apple"),
    ([0xa4, 0x5e, 0x60], "Apple"),
    ([0xac, 0xbc, 0x32], "Apple"),
    ([0xf0, 0x18, 0x98], "Apple"),
    ([0xb8, 0x27, 0xeb], "Raspberry Pi"),
    ([0x28, 0xcd, 0xc1], "Raspberry Pi"),
    ([0xd8, 0x3a, 0xdd], "Raspberry Pi"),
    ([0xdc, 0xa6, 0x32], "Raspberry Pi"),
    ([0xe4, 0x5f, 0x01], "Raspberry Pi"),
    // Virtual machines
    ([0x00, 0x15, 0x5d], "Hyper-V"),
    ([0x00, 0x05, 0x69], "VMware"),
    ([0x00, 0x0c, 0x29], "VMware"),
    ([0x00, 0x1c, 0x14], "VMware"),
    ([0x00, 0x50, 0x56], "VMware"),
    ([0x08, 0x00, 0x27], "VirtualBox"),
    ([0xbc, 0x24, 0x11], "Proxmox"),
    // Printers
    ([0x00, 0x80, 0x77], "Brother"),
    ([0x00, 0x1b, 0xa9], "Brother"),
    ([0x30, 0x05, 0x5c], "Brother"),
    ([0x3c, 0x2a, 0xf4], "Brother"),
    ([0x00, 0x00, 0x85], "Canon"),
    ([0x00, 0x1e, 0x8f], "Canon"),
    ([0x18, 0x0c, 0xac], "Canon"),
    ([0x2c, 0x9e, 0xfc], "Canon"),
    ([0x88, 0x87, 0x17], "Canon"),
    ([0xf4, 0x81, 0x39], "Canon"),
    ([0x00, 0x00, 0x74], "Ricoh"),
    ([0x00, 0x26, 0x73], "Ricoh"),
    ([0x58, 0x38, 0x79], "Ricoh"),
    ([0x00, 0x00, 0xaa], "Xerox"),
    ([0x9c, 0x93, 0x4e], "Xerox"),
    ([0x00, 0x04, 0x00], "Lexmark"),
    ([0x00, 0x20, 0x00], "Lexmark"),
    ([0x00, 0xc0, 0xee], "Kyocera"),
    ([0x00, 0x17, 0xc8], "Kyocera"),
    ([0x00, 0x20, 0x6b], "Konica Minolta"),
    // Cameras, phones, power
    ([0x00, 0x40, 0x8c], "Axis"),
    ([0xac, 0xcc, 0x8e], "Axis"),
    ([0xb8, 0xa4, 0x4f], "Axis"),
    ([0x28, 0x57, 0xbe], "Hikvision"),
    ([0x44, 0x19, 0xb6], "Hikvision"),
    ([0x4c, 0xbd, 0x8f], "Hikvision"),
    ([0x54, 0xc4, 0x15], "Hikvision"),
    ([0xbc, 0xad, 0x28], "Hikvision"),
    ([0xc0, 0x56, 0xe3], "Hikvision"),
    ([0xc4, 0x2f, 0x90], "Hikvision"),
    ([0x00, 0x15, 0x65], "Yealink"),
    ([0x80, 0x5e, 0xc0], "Yealink"),
    ([0x00, 0x04, 0xf2], "Polycom"),
    ([0x64, 0x16, 0x7f], "Polycom"),
    ([0x00, 0xc0, 0xb7], "APC"),
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn known_vendors() {
        assert_eq!(lookup(mac("00:11:32:12:34:56")), Vendor::Known("Synology"));
        assert_eq!(lookup(mac("F0:9F:C2:00:00:01")), Vendor::Known("Ubiquiti"));
        assert_eq!(lookup(mac("00-50-56-aa-bb-cc")), Vendor::Known("VMware"));
        assert_eq!(lookup(mac("00:15:5d:01:02:03")), Vendor::Known("Hyper-V"));
        assert_eq!(
            lookup(mac("b8:27:eb:00:00:00")).name(),
            Some("Raspberry Pi")
        );
    }

    #[test]
    fn unknown_prefix() {
        let v = lookup(mac("00:00:01:00:00:00"));
        assert_eq!(v, Vendor::Unknown);
        assert_eq!((v.name(), v.label()), (None, None));
    }

    #[test]
    fn locally_administered_is_not_guessed() {
        // Same bytes as a Synology prefix, but with the local bit set.
        let v = lookup(mac("02:11:32:12:34:56"));
        assert_eq!(v, Vendor::Randomised);
        assert_eq!((v.name(), v.label()), (None, Some("random MAC")));
        for b0 in ["da", "a6", "7e", "f2"] {
            let m = mac(&format!("{b0}:12:34:56:78:9a"));
            assert_eq!(lookup(m), Vendor::Randomised, "{m}");
        }
        assert_eq!(lookup(mac("52:54:00:12:34:56")), Vendor::Known("QEMU/KVM"));
    }

    #[test]
    fn table_is_sane() {
        let mut seen = HashSet::new();
        for (oui, name) in OUIS {
            assert!(seen.insert(*oui), "duplicate prefix {oui:02x?}");
            assert_eq!(oui[0] & 0x03, 0, "{name} {oui:02x?} is not a vendor prefix");
            assert!(!name.is_empty() && name.len() <= 16, "{name:?}");
            assert!(name.chars().all(|c| c.is_ascii_graphic() || c == ' '));
        }
        for (oui, _) in LOCAL_CONVENTIONS {
            assert_ne!(oui[0] & 0x02, 0, "conventions are local addresses");
        }
    }
}
