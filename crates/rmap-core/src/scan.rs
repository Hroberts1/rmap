//! Scan techniques.

use crate::Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum ScanType {
    /// Full TCP handshake through the OS. No privileges needed.
    #[default]
    Connect,
    /// Half-open TCP scan with hand-built SYN packets. Needs raw sockets.
    Syn,
    /// UDP scan with protocol-aware payloads. Needs raw sockets to read
    /// ICMP port-unreachable replies.
    Udp,
}

impl ScanType {
    pub const ALL: [ScanType; 3] = [ScanType::Connect, ScanType::Syn, ScanType::Udp];

    pub fn label(self) -> &'static str {
        match self {
            ScanType::Connect => "TCP connect",
            ScanType::Syn => "TCP SYN",
            ScanType::Udp => "UDP",
        }
    }

    pub fn protocol(self) -> Protocol {
        match self {
            ScanType::Connect | ScanType::Syn => Protocol::Tcp,
            ScanType::Udp => Protocol::Udp,
        }
    }

    /// Whether this scan needs root / `CAP_NET_RAW`.
    pub fn needs_raw_sockets(self) -> bool {
        !matches!(self, ScanType::Connect)
    }
}
