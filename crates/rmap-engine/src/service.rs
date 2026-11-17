//! Service detection hook (Milestone 3).
//!
//! The engine calls [`Detection::identify`] for each open port once its
//! `Port` event is sent. Detection has its own concurrency limit, separate
//! from probe slots, so slow banner reads can't starve the port scan. It
//! runs inside the probe task, which the host's `JoinSet` owns, so stopping
//! the scan cancels it like any probe.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use rmap_core::{Protocol, ScanEvent, Timing};
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

    /// Detect the service on an open port and report it. UDP plugs in here
    /// once `rmap_detect` has UDP probes; it already accepts the protocol.
    pub async fn identify(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
        tx: &UnboundedSender<ScanEvent>,
    ) {
        let Ok(_permit) = self.slots.acquire().await else {
            return;
        };
        self.attempted.fetch_add(1, Ordering::Relaxed);
        let Some(service) = rmap_detect::detect(ip, port, protocol, &self.timing).await else {
            return;
        };
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
            service,
        });
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
