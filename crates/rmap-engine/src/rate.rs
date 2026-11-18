//! A send-rate limiter for raw packets.
//!
//! Connect scans are paced by the kernel's handshake; raw scans can send as
//! fast as the CPU allows, which floods slow links and drops replies. Each
//! timing template gets a packet-per-second ceiling.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use rmap_core::Timing;

/// Packets per second allowed by a timing template. The slow templates are
/// also paced by their per-probe delay, so their limit rarely binds.
pub fn packet_rate(timing: &Timing) -> u32 {
    match timing.level {
        0 => 1,
        1 => 2,
        2 => 20,
        3 => 5_000,
        4 => 20_000,
        _ => 50_000,
    }
}

/// Spaces sends evenly at a fixed rate. Waiters reserve the next free slot,
/// so concurrent probes share the budget fairly.
#[derive(Debug)]
pub struct RateLimiter {
    interval: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    pub fn per_second(pps: u32) -> Self {
        RateLimiter {
            interval: Duration::from_secs(1) / pps.max(1),
            next: Mutex::new(Instant::now()),
        }
    }

    pub fn for_timing(timing: &Timing) -> Self {
        Self::per_second(packet_rate(timing))
    }

    /// Wait until this caller may send one packet.
    pub async fn wait(&self) {
        let at = {
            let mut next = self.next.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            let at = (*next).max(now);
            *next = at + self.interval;
            at
        };
        tokio::time::sleep_until(at.into()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faster_templates_send_faster() {
        let rates: Vec<u32> = (0..=5).map(|l| packet_rate(&Timing::template(l))).collect();
        assert!(rates.windows(2).all(|w| w[0] < w[1]), "{rates:?}");
    }

    #[tokio::test]
    async fn spaces_packets_out() {
        let limiter = RateLimiter::per_second(1000);
        let started = Instant::now();
        for _ in 0..21 {
            limiter.wait().await;
        }
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[tokio::test]
    async fn zero_rate_does_not_divide_by_zero() {
        let limiter = RateLimiter::per_second(0);
        assert_eq!(limiter.interval, Duration::from_secs(1));
        limiter.wait().await;
    }
}
