//! Core data types shared by the rmap engine and UI: target specifications,
//! port lists, timing templates and scan results.

pub mod mac;
pub mod names;
pub mod ports;
pub mod result;
pub mod scan;
pub mod service;
pub mod target;
pub mod timing;
pub mod vuln;

pub use mac::MacAddr;
pub use names::{HostName, NameSource};
pub use ports::{PortList, service_name};
pub use result::{HostState, PortResult, PortState, Protocol, ScanEvent};
pub use scan::ScanType;
pub use service::{CertInfo, DetectMethod, SILENT_INFO, Service};
pub use target::{Target, parse_targets};
pub use timing::Timing;
pub use vuln::{VulnCheck, VulnData, VulnSeverity, Vulnerability};

/// Error returned when user input cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// Parse an unsigned number written only with ASCII digits. Unlike
/// `str::parse`, this rejects a leading `+`.
pub(crate) fn parse_digits<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError(msg.into()))
}
