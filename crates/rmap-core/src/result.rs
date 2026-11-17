//! Scan results and the event stream the engine sends to the UI.

use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortState {
    /// Something accepted the connection.
    Open,
    /// The host answered with a reset: reachable, nothing listening.
    Closed,
    /// No answer, or an ICMP error: a firewall is likely in the way.
    Filtered,
}

impl PortState {
    pub fn as_str(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    /// Answered a discovery probe.
    Up,
    /// No answer to any discovery probe.
    Down,
    /// Discovery was skipped; the host is scanned anyway.
    Assumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    /// Time to connect, when the port answered.
    pub rtt: Option<Duration>,
}

/// Progress and results emitted by the engine while a scan runs.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// The scan is underway and these are its totals.
    Started { hosts: u64, ports_per_host: usize },
    /// Discovery finished for a host.
    Host {
        ip: IpAddr,
        hostname: Option<String>,
        state: HostState,
        rtt: Option<Duration>,
    },
    /// An open port. Closed and filtered ports are counted in `HostDone`
    /// instead, so large scans don't flood the UI.
    Port { ip: IpAddr, result: PortResult },
    /// Every port on this host has been probed.
    HostDone {
        ip: IpAddr,
        closed: u32,
        filtered: u32,
        elapsed: Duration,
    },
    /// Something worth telling the user that didn't stop the scan.
    Warning(String),
    /// The scan completed.
    Finished { elapsed: Duration },
}
