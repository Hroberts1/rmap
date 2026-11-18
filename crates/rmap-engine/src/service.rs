//! Service detection hook (Milestone 3).
//!
//! The engine calls [`Detection::identify`] for each open TCP port once its
//! `Port` event is sent, and [`Detection::identify_udp`] for open and
//! open|filtered UDP ports, which sends the `Port` event itself so a reply
//! can upgrade the state first. Detection has its own concurrency limit, separate
//! from probe slots, so slow banner reads can't starve the port scan. It
//! runs inside the probe task, which the host's `JoinSet` owns, so stopping
//! the scan cancels it like any probe.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use rmap_core::{PortResult, PortState, Protocol, ScanEvent, Timing};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::UnboundedSender;

pub(crate) struct Detection {
    slots: Semaphore,
    timing: Timing,
    /// Ports where a rule or TLS matched (not port-table guesses).
    pub identified: AtomicU64,
    pub attempted: AtomicU64,
}

impl Detection {
    pub fn new(timing: Timing) -> Detection {
        let parallelism = parallelism(&timing);
        rmap_log::info!(
            "service detection on: up to {parallelism} ports at once, {:?} per port",
            rmap_detect::budget(&timing)
        );
        Detection {
            slots: Semaphore::new(parallelism),
            timing,
            identified: AtomicU64::new(0),
            attempted: AtomicU64::new(0),
        }
    }

    /// Detect the service on an open port and report it, returning it so
    /// the caller can feed its CPEs into vulnerability matching (M4)
    /// without this module needing to know that exists.
    pub async fn identify(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
        tx: &UnboundedSender<ScanEvent>,
    ) -> Option<rmap_core::Service> {
        let detected = self.detect(ip, port, protocol).await?;
        self.report(ip, port, protocol, detected.service?, tx)
    }

    /// For a UDP port not yet reported: detect, upgrade open|filtered to
    /// open if any probe got a reply, then send `Port` and `Service` in
    /// that order.
    pub async fn identify_udp(
        &self,
        ip: IpAddr,
        mut result: PortResult,
        tx: &UnboundedSender<ScanEvent>,
    ) -> Option<rmap_core::Service> {
        let port = result.port;
        let detected = self.detect(ip, port, Protocol::Udp).await;
        if result.state == PortState::OpenFiltered && detected.as_ref().is_some_and(|d| d.answered)
        {
            rmap_log::debug!("{ip}:{port}/udp answered a detection probe: open");
            result.state = PortState::Open;
        }
        let _ = tx.send(ScanEvent::Port { ip, result });
        self.report(ip, port, Protocol::Udp, detected?.service?, tx)
    }

    async fn detect(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
    ) -> Option<rmap_detect::Detected> {
        let _permit = self.slots.acquire().await.ok()?;
        self.attempted.fetch_add(1, Ordering::Relaxed);
        Some(rmap_detect::detect_port(ip, port, protocol, &self.timing).await)
    }

    fn report(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
        service: rmap_core::Service,
        tx: &UnboundedSender<ScanEvent>,
    ) -> Option<rmap_core::Service> {
        if service.method != rmap_core::DetectMethod::PortTable {
            self.identified.fetch_add(1, Ordering::Relaxed);
        }
        rmap_log::debug!(
            "service {ip}:{port}/{} = {} {} ({:?}, confidence {})",
            protocol.as_str(),
            service.name,
            service.version_label().unwrap_or_default(),
            service.method,
            service.confidence
        );
        let _ = tx.send(ScanEvent::Service {
            ip,
            protocol,
            port,
            service: service.clone(),
        });
        Some(service)
    }
}

/// Ports detected at once: an eighth of the probe concurrency, 1-64.
fn parallelism(timing: &Timing) -> usize {
    (timing.concurrency / 8).clamp(1, 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallelism_follows_timing() {
        assert_eq!(parallelism(&Timing::template(0)), 1);
        assert_eq!(parallelism(&Timing::template(3)), 50);
        assert_eq!(parallelism(&Timing::template(5)), 64);
    }
}
