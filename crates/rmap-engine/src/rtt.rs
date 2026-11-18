//! Per-host adaptive probe timeouts.
//!
//! Each host keeps a smoothed round-trip time (SRTT) and its variation
//! (RTTVAR), updated from every answered probe as in RFC 6298. A probe then
//! waits `SRTT + 4 * RTTVAR`, so a LAN host answering in a millisecond isn't
//! waited on for the full template timeout, and a slow WAN host gets longer
//! than the template before its ports are called filtered.
//!
//! Bounds, chosen to be conservative:
//! - Until a host has answered anything, probes wait the template's
//!   `connect_timeout`, exactly as before adaptation existed.
//! - The adapted timeout never drops below `min_rtt_timeout` (100-400 ms in
//!   the templates). That floor is tens to hundreds of times a LAN RTT, so a
//!   scheduling hiccup or a jittery link can't turn an open port filtered.
//!   It never rises above `max_rtt_timeout` (or `connect_timeout`, if that
//!   is larger), so one huge sample can't stall the scan.
//! - Retries double the wait each time, up to the larger of the template
//!   timeout and the adapted one, so a lost reply gets a more patient retry.
//! - Timeouts on unanswered probes don't inflate the estimate: filtered
//!   ports time out by design, and that says nothing about the path.
//!
//! T0 and T1 set both bounds to `connect_timeout`, so they stay fixed.

use std::sync::Mutex;
use std::time::Duration;

use rmap_core::Timing;

/// SRTT/RTTVAR in microseconds. Saturating integer maths, so zero or absurd
/// samples can't panic or overflow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttEstimator {
    /// `(srtt, rttvar)`, `None` until the first sample.
    state: Option<(u64, u64)>,
}

impl RttEstimator {
    /// Fold in one measured round trip.
    pub fn sample(&mut self, rtt: Duration) {
        let r = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
        self.state = Some(match self.state {
            None => (r, r / 2),
            Some((srtt, rttvar)) => {
                // RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R|; SRTT = 7/8 SRTT + 1/8 R.
                let rttvar = rttvar - rttvar / 4 + srtt.abs_diff(r) / 4;
                (srtt - srtt / 8 + r / 8, rttvar)
            }
        });
    }

    /// The smoothed RTT, once anything has been measured.
    pub fn srtt(&self) -> Option<Duration> {
        self.state.map(|(srtt, _)| Duration::from_micros(srtt))
    }

    /// How long attempt `try_no` (0 for the first) should wait for a reply.
    pub fn timeout(&self, timing: &Timing, try_no: u8) -> Duration {
        let base = match self.state {
            None => timing.connect_timeout,
            Some((srtt, rttvar)) => {
                let rto = Duration::from_micros(srtt.saturating_add(rttvar.saturating_mul(4)));
                let floor = timing.min_rtt_timeout.min(timing.connect_timeout);
                let ceiling = timing.max_rtt_timeout.max(timing.connect_timeout);
                rto.max(floor).min(ceiling)
            }
        };
        let backoff = 2u32.saturating_pow(u32::from(try_no));
        base.checked_mul(backoff)
            .unwrap_or(Duration::MAX)
            .min(base.max(timing.connect_timeout))
    }
}

/// One host's estimator, shared by its probe tasks.
#[derive(Debug, Default)]
pub struct HostRtt(Mutex<RttEstimator>);

impl HostRtt {
    /// Start from the discovery round trip, when there was one.
    pub fn seeded(rtt: Option<Duration>) -> Self {
        let mut est = RttEstimator::default();
        if let Some(rtt) = rtt {
            est.sample(rtt);
        }
        HostRtt(Mutex::new(est))
    }

    pub fn sample(&self, rtt: Duration) {
        self.lock().sample(rtt);
    }

    pub fn timeout(&self, timing: &Timing, try_no: u8) -> Duration {
        self.lock().timeout(timing, try_no)
    }

    /// Copy of the current estimate, for logging.
    pub fn snapshot(&self) -> RttEstimator {
        *self.lock()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RttEstimator> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// T3-like bounds: 1500 ms initial, 100 ms - 4 s adaptive.
    fn timing() -> Timing {
        Timing {
            connect_timeout: ms(1500),
            min_rtt_timeout: ms(100),
            max_rtt_timeout: ms(4000),
            retries: 2,
            ..Timing::template(3)
        }
    }

    fn after(samples: &[Duration]) -> RttEstimator {
        let mut e = RttEstimator::default();
        for &s in samples {
            e.sample(s);
        }
        e
    }

    #[test]
    fn unmeasured_host_uses_the_template_timeout() {
        let e = RttEstimator::default();
        assert_eq!(e.srtt(), None);
        for try_no in 0..=3 {
            assert_eq!(e.timeout(&timing(), try_no), ms(1500));
        }
    }

    #[test]
    fn first_sample_follows_rfc_6298() {
        // SRTT = R, RTTVAR = R/2, so RTO = 3R.
        let e = after(&[ms(200)]);
        assert_eq!(e.srtt(), Some(ms(200)));
        assert_eq!(e.timeout(&timing(), 0), ms(600));
    }

    #[test]
    fn steady_samples_converge() {
        let e = after(&[ms(100); 64]);
        let srtt = e.srtt().unwrap();
        assert!(srtt.abs_diff(ms(100)) < ms(1), "{srtt:?}");
        // RTTVAR decays towards zero, so RTO approaches SRTT (above the floor).
        let t = e.timeout(&timing(), 0);
        assert!(t >= ms(100) && t < ms(110), "{t:?}");
    }

    #[test]
    fn fast_host_is_clamped_to_the_floor() {
        let e = after(&[Duration::from_micros(300); 10]);
        assert_eq!(e.timeout(&timing(), 0), ms(100));
    }

    #[test]
    fn zero_rtt_is_clamped_to_the_floor() {
        let e = after(&[Duration::ZERO; 5]);
        assert_eq!(e.srtt(), Some(Duration::ZERO));
        assert_eq!(e.timeout(&timing(), 0), ms(100));
    }

    #[test]
    fn huge_rtt_is_clamped_to_the_ceiling_without_overflow() {
        for huge in [Duration::from_secs(3600), Duration::MAX] {
            let e = after(&[huge, huge, Duration::ZERO, huge]);
            for try_no in [0, 1, 7, 255] {
                assert_eq!(e.timeout(&timing(), try_no), ms(4000), "{huge:?} {try_no}");
            }
        }
    }

    #[test]
    fn slow_host_can_exceed_the_template_timeout() {
        let e = after(&[ms(2000); 8]);
        let t = e.timeout(&timing(), 0);
        assert!(t > ms(1500) && t <= ms(4000), "{t:?}");
    }

    #[test]
    fn a_spike_widens_the_timeout_then_decays() {
        let steady = after(&[ms(20); 20]);
        let mut spiked = steady;
        spiked.sample(ms(500));
        let wide = spiked.timeout(&timing(), 0);
        assert!(
            wide > ms(400),
            "one spike should make probes much more patient: {wide:?}"
        );
        for _ in 0..40 {
            spiked.sample(ms(20));
        }
        assert_eq!(spiked.timeout(&timing(), 0), steady.timeout(&timing(), 0));
    }

    #[test]
    fn retries_back_off_up_to_the_template_timeout() {
        let e = after(&[Duration::from_micros(500); 10]);
        let t = timing();
        assert_eq!(e.timeout(&t, 0), ms(100));
        assert_eq!(e.timeout(&t, 1), ms(200));
        assert_eq!(e.timeout(&t, 2), ms(400));
        assert_eq!(e.timeout(&t, 4), ms(1500));
        assert_eq!(e.timeout(&t, 255), ms(1500));
    }

    #[test]
    fn loss_does_not_shrink_or_inflate_the_estimate() {
        // A timed-out probe records nothing, so the estimate is unchanged
        // and the retry simply waits longer.
        let host = HostRtt::seeded(Some(ms(10)));
        let before = host.snapshot();
        let first = host.timeout(&timing(), 0);
        let retry = host.timeout(&timing(), 1);
        assert_eq!(host.snapshot(), before);
        assert_eq!(retry, first * 2);
    }

    #[test]
    fn floor_never_exceeds_a_short_template_timeout() {
        let t = Timing {
            connect_timeout: ms(50),
            ..timing()
        };
        let e = after(&[Duration::from_micros(10); 4]);
        assert_eq!(e.timeout(&t, 0), ms(50));
    }

    #[test]
    fn inverted_bounds_do_not_panic() {
        let t = Timing {
            min_rtt_timeout: ms(5000),
            max_rtt_timeout: ms(10),
            ..timing()
        };
        let e = after(&[ms(1)]);
        assert_eq!(e.timeout(&t, 0), ms(1500));
    }

    #[test]
    fn fixed_templates_never_adapt() {
        for level in [0, 1] {
            let t = Timing::template(level);
            for samples in [&[ms(1); 10][..], &[Duration::from_secs(60)][..]] {
                let e = after(samples);
                for try_no in 0..=t.retries {
                    assert_eq!(e.timeout(&t, try_no), t.connect_timeout, "T{level}");
                }
            }
        }
    }

    #[test]
    fn templates_have_sane_bounds() {
        for level in 0..=5 {
            let t = Timing::template(level);
            assert!(t.min_rtt_timeout <= t.connect_timeout, "T{level}");
            assert!(t.connect_timeout <= t.max_rtt_timeout, "T{level}");
            assert!(t.min_rtt_timeout >= ms(100), "T{level}");
        }
    }

    #[test]
    fn seeding_matches_a_first_sample() {
        assert_eq!(HostRtt::seeded(Some(ms(30))).snapshot(), after(&[ms(30)]));
        assert_eq!(HostRtt::seeded(None).snapshot(), RttEstimator::default());
    }

    #[test]
    fn randomized_samples_stay_within_bounds() {
        // xorshift: deterministic, no dependency.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let t = timing();
        let mut e = RttEstimator::default();
        for _ in 0..10_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let micros = match x % 4 {
                0 => 0,
                1 => x % 1_000,
                2 => x % 10_000_000,
                _ => x,
            };
            e.sample(Duration::from_micros(micros));
            let try_no = (x >> 56) as u8;
            let to = e.timeout(&t, try_no);
            assert!(to >= ms(100) && to <= ms(4000), "{to:?}");
        }
    }
}
