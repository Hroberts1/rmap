//! Scan results and the event stream the engine sends to the UI.

use std::net::IpAddr;
use std::time::Duration;

use crate::service::Service;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum PortState {
    /// Something accepted the connection or answered the probe.
    Open,
    /// The host answered with a reset or ICMP port-unreachable: reachable,
    /// nothing listening.
    Closed,
    /// No answer, or an ICMP error: a firewall is likely in the way.
    Filtered,
    /// No answer to a probe that an open port may legitimately ignore
    /// (typical for UDP). Can't tell open from filtered.
    OpenFiltered,
}

impl PortState {
    pub fn as_str(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum HostState {
    /// Answered a discovery probe.
    Up,
    /// No answer to any discovery probe.
    Down,
    /// Discovery was skipped; the host is scanned anyway.
    Assumed,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    /// Time to answer, when the port answered.
    pub rtt: Option<Duration>,
    /// Filled in by service detection, possibly after the port is reported.
    pub service: Option<Service>,
    /// Filled in by vulnerability matching, possibly after the port is
    /// reported. Empty, not missing, when detection ran and found nothing.
    #[cfg_attr(feature = "serde", serde(default))]
    pub vulnerabilities: Vec<crate::Vulnerability>,
}

impl PortResult {
    pub fn new(port: u16, protocol: Protocol, state: PortState, rtt: Option<Duration>) -> Self {
        PortResult {
            port,
            protocol,
            state,
            rtt,
            service: None,
            vulnerabilities: Vec::new(),
        }
    }
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
    /// The host's hardware address, learned from its ARP reply during
    /// discovery. Sent after `Host`, and only for hosts on a directly
    /// connected Ethernet subnet scanned with raw sockets.
    Mac { ip: IpAddr, mac: crate::MacAddr },
    /// Names the host answered to: reverse DNS, NetBIOS and mDNS, best
    /// first. Sent after `Host` (and `Mac`), possibly while its ports are
    /// still being scanned, and never when `names` would be empty.
    Hostnames {
        ip: IpAddr,
        names: Vec<crate::HostName>,
    },
    /// An open (or open|filtered) port. Closed and filtered ports are
    /// counted in `HostDone` instead, so large scans don't flood the UI.
    Port { ip: IpAddr, result: PortResult },
    /// Service detection identified what is listening on a port that was
    /// already reported with `Port`.
    Service {
        ip: IpAddr,
        protocol: Protocol,
        port: u16,
        service: Service,
    },
    /// Vulnerability matching found potential CVEs for a service already
    /// reported with `Service`. Never sent when the list would be empty.
    Vulnerabilities {
        ip: IpAddr,
        protocol: Protocol,
        port: u16,
        findings: Vec<crate::Vulnerability>,
    },
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
