//! Picks how ports are probed and hosts are discovered.
//!
//! Raw sockets give SYN and UDP scans and ICMP/ARP discovery, but need
//! Linux and root or `CAP_NET_RAW`. Without them the engine falls back to
//! methods any user can run, and says so once: SYN becomes TCP connect, UDP
//! becomes connected-socket probing, and discovery uses the TCP connect
//! ping.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rmap_core::{MacAddr, PortResult, ScanType, Timing};

use crate::rtt::HostRtt;
use crate::{Stats, tcp, udp};

/// The probing method chosen for a whole scan.
pub(crate) enum Prober {
    /// No raw sockets: plain sockets for everything.
    Unprivileged,
    #[cfg(target_os = "linux")]
    Raw(Arc<crate::raw::RawScanner>),
}

/// Why raw sockets couldn't be used, or `Ok` with a working backend.
#[cfg(target_os = "linux")]
fn open_raw(scan_type: ScanType, timing: &Timing) -> Result<Prober, String> {
    match crate::raw::RawScanner::open(scan_type, timing) {
        Ok(raw) => Ok(Prober::Raw(Arc::new(raw))),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err("needs root or CAP_NET_RAW".into())
        }
        Err(e) => Err(format!("could not open raw sockets ({e})")),
    }
}

#[cfg(not(target_os = "linux"))]
fn open_raw(_: ScanType, _: &Timing) -> Result<Prober, String> {
    Err("raw sockets are only supported on Linux so far".into())
}

impl Prober {
    /// Choose a backend. Returns a warning for the user when the scan they
    /// asked for had to be downgraded.
    pub(crate) fn select(
        scan_type: ScanType,
        discovery: bool,
        timing: &Timing,
    ) -> (Prober, Option<String>) {
        if !scan_type.needs_raw_sockets() && !discovery {
            return (Prober::Unprivileged, None);
        }
        let reason = match open_raw(scan_type, timing) {
            Ok(p) => return (p, None),
            Err(reason) => reason,
        };
        let warning = match scan_type {
            ScanType::Syn => Some(format!("SYN scan {reason}; falling back to TCP connect")),
            ScanType::Udp => Some(format!(
                "raw UDP scan {reason}; falling back to unprivileged UDP probes, \
                 which may miss some closed ports"
            )),
            ScanType::Connect => None,
        };
        // Discovery quietly uses the connect ping; only log why.
        rmap_log::info!("raw sockets unavailable ({reason}); using unprivileged probes");
        (Prober::Unprivileged, warning)
    }

    /// Short name for logs.
    pub(crate) fn describe(&self) -> &'static str {
        match self {
            Prober::Unprivileged => "unprivileged sockets",
            #[cfg(target_os = "linux")]
            Prober::Raw(_) => "raw sockets",
        }
    }

    /// Prepare to probe one host.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    pub(crate) fn for_host(&self, ip: IpAddr, scan_type: ScanType) -> HostProber {
        match self {
            #[cfg(target_os = "linux")]
            Prober::Raw(raw) => match raw.route(ip) {
                Ok(route) => {
                    rmap_log::debug!("raw probes to {ip} leave from {}", route.src());
                    HostProber::Raw {
                        raw: raw.clone(),
                        route,
                        scan_type,
                    }
                }
                Err(e) => {
                    rmap_log::debug!("no raw route to {ip} ({e}); using unprivileged probes");
                    HostProber::Unprivileged(scan_type)
                }
            },
            Prober::Unprivileged => HostProber::Unprivileged(scan_type),
        }
    }
}

/// How to probe one host. Cheap to clone into each probe task.
#[derive(Clone)]
pub(crate) enum HostProber {
    Unprivileged(ScanType),
    #[cfg(target_os = "linux")]
    Raw {
        raw: Arc<crate::raw::RawScanner>,
        route: crate::raw::Route,
        scan_type: ScanType,
    },
}

impl HostProber {
    /// Round-trip time if the host is up, and its MAC address when the
    /// probe that answered was ARP.
    pub(crate) async fn ping(
        &self,
        ip: IpAddr,
        timing: &Timing,
        stats: &Arc<Stats>,
    ) -> Option<(Duration, Option<MacAddr>)> {
        match self {
            HostProber::Unprivileged(_) => {
                tcp::ping(ip, timing, stats).await.map(|rtt| (rtt, None))
            }
            #[cfg(target_os = "linux")]
            HostProber::Raw { raw, route, .. } => raw.ping(*route, timing, stats).await,
        }
    }

    pub(crate) async fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timing: &Timing,
        stats: &Stats,
        rtt: &HostRtt,
    ) -> PortResult {
        match self {
            HostProber::Unprivileged(ScanType::Udp) => {
                udp::probe(ip, port, timing, stats, rtt).await
            }
            HostProber::Unprivileged(_) => tcp::probe(ip, port, timing, stats, rtt).await,
            #[cfg(target_os = "linux")]
            HostProber::Raw {
                scan_type: ScanType::Connect,
                ..
            } => tcp::probe(ip, port, timing, stats, rtt).await,
            #[cfg(target_os = "linux")]
            HostProber::Raw { raw, route, .. } => {
                raw.probe(*route, port, timing, stats, rtt).await
            }
        }
    }
}
