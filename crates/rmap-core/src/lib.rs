//! Core data types shared by the rmap engine and UI: target specifications,
//! port lists, timing templates and scan results.

pub mod ports;
pub mod result;
pub mod target;
pub mod timing;

pub use ports::{PortList, service_name};
pub use result::{HostState, PortResult, PortState, ScanEvent};
pub use target::{Target, parse_targets};
pub use timing::Timing;

/// Error returned when user input cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError(msg.into()))
}
