//! The report data model and its on-disk JSON shape.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmap_core::{HostName, HostState, MacAddr, PortResult, PortState, ScanType, VulnData};
use rmap_log::Timestamp;
use serde::{Deserialize, Serialize};

/// Version of the report file format. Bump it when a change would make old
/// readers misread new files; adding optional fields doesn't need a bump.
pub const FORMAT_VERSION: u32 = 1;

/// How the scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Still running when the report was taken.
    Running,
    /// Every host and port was probed.
    Completed,
    /// The user stopped the scan; results are partial.
    Stopped,
    /// The engine died (most likely a panic); results are partial.
    Failed,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Completed => "completed",
            RunStatus::Stopped => "stopped",
            RunStatus::Failed => "failed",
        }
    }

    /// Whether the results cover the whole scan.
    pub fn is_complete(self) -> bool {
        self == RunStatus::Completed
    }
}

/// What was asked for, in enough detail to repeat or compare the scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSummary {
    /// Targets exactly as the user typed them.
    pub targets: String,
    /// The port list as compact ranges, e.g. `22,80,443,8000-8100`.
    pub ports: String,
    pub port_count: usize,
    pub scan_type: ScanType,
    pub timing_level: u8,
    pub timing_name: String,
    pub discovery: bool,
    pub service_detection: bool,
    /// Addresses excluded from the scan, exactly as typed; empty if none.
    /// Kept so the report documents the scan's authorised scope.
    #[serde(default)]
    pub exclude: String,
    /// Cap on probes started per second; `None` means unlimited.
    #[serde(default)]
    pub max_rate: Option<u32>,
    /// Host names were looked up (reverse DNS, NetBIOS, mDNS).
    #[serde(default)]
    pub resolve_names: bool,
    /// DNS server used for reverse lookups, if the user chose one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_server: Option<IpAddr>,
}

/// One host's results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostReport {
    pub ip: IpAddr,
    #[serde(default)]
    pub hostname: Option<String>,
    pub state: HostState,
    #[serde(default)]
    pub rtt: Option<Duration>,
    /// Open and open|filtered ports, sorted by (port, protocol).
    #[serde(default)]
    pub ports: Vec<PortResult>,
    #[serde(default)]
    pub closed: u32,
    #[serde(default)]
    pub filtered: u32,
    /// Every port on this host was probed.
    #[serde(default)]
    pub complete: bool,
    /// Hardware address, when discovery learned it over ARP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// Vendor of `mac` from rmap's built-in OUI table, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Names the host answered to (reverse DNS, NetBIOS, mDNS), best
    /// first. The first also fills `hostname` when no name was typed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<HostName>,
}

impl HostReport {
    pub fn new(ip: IpAddr, hostname: Option<String>, state: HostState) -> Self {
        HostReport {
            ip,
            hostname,
            state,
            rtt: None,
            ports: Vec::new(),
            closed: 0,
            filtered: 0,
            complete: state == HostState::Down,
            mac: None,
            vendor: None,
            names: Vec::new(),
        }
    }

    /// Up, or assumed up because discovery was off.
    pub fn is_up(&self) -> bool {
        self.state != HostState::Down
    }

    pub fn open_count(&self) -> usize {
        self.ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .count()
    }
}

/// A complete record of one scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub format_version: u32,
    pub rmap_version: String,
    /// When the scan started, as Unix milliseconds (UTC).
    pub started_ms: i64,
    /// When it ended; `None` while running.
    #[serde(default)]
    pub finished_ms: Option<i64>,
    pub status: RunStatus,
    pub config: ConfigSummary,
    /// Hosts in address order.
    pub hosts: Vec<HostReport>,
    /// The CVE database matched against; `None` when matching was off or
    /// no database opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_data: Option<VulnData>,
}

impl ScanReport {
    /// An empty report for a scan that starts at `started_ms`.
    pub fn new(config: ConfigSummary, started_ms: i64) -> Self {
        ScanReport {
            format_version: FORMAT_VERSION,
            rmap_version: env!("CARGO_PKG_VERSION").to_string(),
            started_ms,
            finished_ms: None,
            status: RunStatus::Running,
            config,
            hosts: Vec::new(),
            vuln_data: None,
        }
    }

    pub fn started(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.started_ms)
    }

    pub fn finished(&self) -> Option<Timestamp> {
        self.finished_ms.map(Timestamp::from_unix_millis)
    }

    pub fn elapsed(&self) -> Duration {
        let end = self.finished_ms.unwrap_or(self.started_ms);
        Duration::from_millis(end.saturating_sub(self.started_ms).max(0) as u64)
    }

    pub fn hosts_up(&self) -> usize {
        self.hosts.iter().filter(|h| h.is_up()).count()
    }

    pub fn open_ports(&self) -> usize {
        self.hosts.iter().map(HostReport::open_count).sum()
    }

    pub fn host(&self, ip: IpAddr) -> Option<&HostReport> {
        self.hosts.iter().find(|h| h.ip == ip)
    }

    /// One line for lists: `2026-11-17 14:30 · 10.0.0.0/24 · 3/256 up · 7 open`.
    pub fn summary(&self) -> String {
        let t = self.started();
        let mut s = format!(
            "{:04}-{:02}-{:02} {:02}:{:02} · {} · {}/{} up · {} open",
            t.year,
            t.month,
            t.day,
            t.hour,
            t.minute,
            self.config.targets,
            self.hosts_up(),
            self.hosts.len(),
            self.open_ports()
        );
        if !self.status.is_complete() {
            s.push_str(&format!(" · {}", self.status.as_str()));
        }
        s
    }
}

/// Current time as Unix milliseconds.
pub fn unix_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Sorted, de-duplicated ports as compact ranges: `[1,2,3,80]` → `1-3,80`.
pub fn port_ranges(ports: &[u16]) -> String {
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end.wrapping_add(1) && end != u16::MAX {
            end = sorted[i + 1];
            i += 1;
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    out.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(port_ranges(&[]), "");
        assert_eq!(port_ranges(&[80]), "80");
        assert_eq!(port_ranges(&[3, 1, 2, 80, 80, 81, 443]), "1-3,80-81,443");
        assert_eq!(port_ranges(&[65534, 65535]), "65534-65535");
        let all: Vec<u16> = (1..=65535).collect();
        assert_eq!(port_ranges(&all), "1-65535");
    }

    #[test]
    fn elapsed_never_negative() {
        let mut r = ScanReport::new(crate::builder::tests::config(), 5_000);
        r.finished_ms = Some(1_000);
        assert_eq!(r.elapsed(), Duration::ZERO);
        r.finished_ms = Some(6_500);
        assert_eq!(r.elapsed(), Duration::from_millis(1_500));
    }
}
