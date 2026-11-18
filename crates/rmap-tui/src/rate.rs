//! Probe rate, ETA and the rate sparkline for the results header.
//!
//! The math is pure: callers pass the time since the scan started, so tests
//! need no clock.

use std::collections::VecDeque;
use std::time::Duration;

/// Samples kept; more than the widest sparkline needs.
const SAMPLES: usize = 32;
const INTERVAL: Duration = Duration::from_secs(1);
/// The rate is averaged over about this long, so one slow second doesn't
/// make the ETA jump.
const WINDOW: Duration = Duration::from_secs(5);
/// No rate or ETA before this much data; the first second is mostly setup.
const MIN_SPAN: Duration = Duration::from_secs(2);
const SPARK_MAX: usize = 12;
/// The bar never shrinks below this to make room for text.
const MIN_BAR: usize = 20;

/// About one `(time since start, probes completed)` sample per second.
#[derive(Debug, Default)]
pub struct RateMeter {
    samples: VecDeque<(Duration, u64)>,
}

impl RateMeter {
    /// Record `completed` at `at`. Calls less than a second after the last
    /// sample are ignored, so this is cheap to call every frame.
    pub fn sample(&mut self, at: Duration, completed: u64) {
        if let Some(&(last, _)) = self.samples.back()
            && at < last + INTERVAL
        {
            return;
        }
        if self.samples.len() == SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back((at, completed));
    }

    /// Probes per second over the last few seconds, once there's enough data.
    pub fn rate(&self) -> Option<f64> {
        let &(now, done) = self.samples.back()?;
        let &(then, before) = self
            .samples
            .iter()
            .find(|(t, _)| now.saturating_sub(*t) <= WINDOW)?;
        let span = now.saturating_sub(then);
        if span < MIN_SPAN {
            return None;
        }
        Some(done.saturating_sub(before) as f64 / span.as_secs_f64())
    }

    /// Probes per second between consecutive samples, oldest first.
    fn rates(&self) -> impl Iterator<Item = f64> + '_ {
        self.samples
            .iter()
            .zip(self.samples.iter().skip(1))
            .map(|(&(t0, c0), &(t1, c1))| {
                let dt = t1.saturating_sub(t0).as_secs_f64();
                if dt > 0.0 {
                    c1.saturating_sub(c0) as f64 / dt
                } else {
                    0.0
                }
            })
    }

    /// The last `width` per-second rates as block characters.
    pub fn sparkline(&self, width: usize) -> String {
        let rates: Vec<f64> = self.rates().collect();
        let shown = &rates[rates.len().saturating_sub(width)..];
        let max = shown.iter().copied().fold(0.0, f64::max);
        shown
            .iter()
            .map(|r| {
                const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
                let level = if max > 0.0 { r / max * 7.0 } else { 0.0 };
                BARS[(level.round() as usize).min(7)]
            })
            .collect()
    }
}

/// Time left at `rate` probes/s, or `None` when it can't be estimated.
pub fn eta(completed: u64, total: u64, rate: Option<f64>) -> Option<Duration> {
    let rate = rate.filter(|r| r.is_finite() && *r > 0.0)?;
    let remaining = total.checked_sub(completed).filter(|r| *r > 0)?;
    // Cap at 100 hours so a near-zero rate can't overflow Duration.
    Some(Duration::from_secs_f64(
        (remaining as f64 / rate).min(360_000.0),
    ))
}

/// `m:ss`, or `h:mm:ss` past an hour.
pub fn clock(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

/// `25400` -> `25,400`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Text beside the progress bar in a row `width` cells wide: the fullest of
/// `done / total probes · rate/s ▂▃▅` that leaves the bar `MIN_BAR` cells.
/// The sparkline goes first, then the rate, then the text altogether.
pub fn progress_text(
    done: u64,
    total: u64,
    rate: Option<f64>,
    meter: &RateMeter,
    width: usize,
) -> String {
    let counts = format!("{} / {} probes", thousands(done), thousands(total));
    let mut options = Vec::new();
    if let Some(r) = rate {
        let with_rate = format!("{counts} · {}/s", thousands(r.round() as u64));
        let spark = meter.sparkline(SPARK_MAX);
        if !spark.is_empty() {
            options.push(format!("{with_rate} {spark}"));
        }
        options.push(with_rate);
    }
    options.push(counts);
    options
        .into_iter()
        .find(|t| t.chars().count() + 1 + MIN_BAR <= width)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// A meter fed `per_sec` probes every second for `n` seconds.
    fn steady(per_sec: u64, n: u64) -> RateMeter {
        let mut m = RateMeter::default();
        for s in 0..=n {
            m.sample(secs(s), s * per_sec);
        }
        m
    }

    #[test]
    fn rate_needs_two_seconds_of_data() {
        let mut m = RateMeter::default();
        assert_eq!(m.rate(), None);
        m.sample(secs(0), 0);
        m.sample(secs(1), 100);
        assert_eq!(m.rate(), None);
        m.sample(secs(2), 200);
        assert_eq!(m.rate(), Some(100.0));
    }

    #[test]
    fn samples_closer_than_a_second_are_ignored() {
        let mut m = RateMeter::default();
        m.sample(secs(0), 0);
        m.sample(Duration::from_millis(500), 999);
        m.sample(Duration::from_millis(50), 999); // clock going backwards
        assert_eq!(m.samples.len(), 1);
    }

    #[test]
    fn rate_follows_the_last_five_seconds() {
        let mut m = steady(1000, 10);
        for s in 11..=16 {
            m.sample(secs(s), 10_000 + (s - 10) * 100);
        }
        assert_eq!(m.rate(), Some(100.0));
    }

    #[test]
    fn stalled_scan_has_zero_rate_and_no_eta() {
        let mut m = RateMeter::default();
        for s in 0..5 {
            m.sample(secs(s), 0);
        }
        assert_eq!(m.rate(), Some(0.0));
        assert_eq!(eta(0, 100, m.rate()), None);
        assert_eq!(m.sparkline(4), "▁▁▁▁");
    }

    #[test]
    fn buffer_stays_bounded() {
        let m = steady(10, 1000);
        assert_eq!(m.samples.len(), SAMPLES);
        assert_eq!(m.rate(), Some(10.0));
    }

    #[test]
    fn counter_going_backwards_does_not_panic() {
        let mut m = RateMeter::default();
        for (s, c) in [(0, 500), (1, 100), (2, 50)] {
            m.sample(secs(s), c);
        }
        assert_eq!(m.rate(), Some(0.0));
        assert_eq!(m.sparkline(5), "▁▁");
    }

    #[test]
    fn eta_math() {
        let mockup = eta(15_840, 25_400, Some(380.0)).unwrap();
        assert_eq!(clock(mockup), "0:25");
        assert_eq!(eta(0, 100, None), None);
        assert_eq!(eta(100, 100, Some(5.0)), None, "nothing left");
        assert_eq!(eta(150, 100, Some(5.0)), None, "completed past total");
        assert_eq!(eta(0, 100, Some(f64::NAN)), None);
        assert_eq!(eta(0, u64::MAX, Some(1e-300)), Some(secs(360_000)));
        // Total growing mid-scan just means more remaining.
        assert_eq!(eta(100, 200, Some(10.0)), Some(secs(10)));
        assert_eq!(eta(100, 400, Some(10.0)), Some(secs(30)));
    }

    #[test]
    fn formatting() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(25_400), "25,400");
        assert_eq!(thousands(u64::MAX), "18,446,744,073,709,551,615");
        assert_eq!(clock(secs(26)), "0:26");
        assert_eq!(clock(secs(42 * 60 + 5)), "42:05");
        assert_eq!(clock(secs(3600 + 61)), "1:01:01");
    }

    #[test]
    fn sparkline_scales_to_the_peak() {
        let mut m = RateMeter::default();
        for (s, c) in [(0, 0), (1, 100), (2, 300), (3, 1000), (4, 1300)] {
            m.sample(secs(s), c);
        }
        assert_eq!(m.sparkline(10), "▂▃█▄");
        assert_eq!(m.sparkline(2), "█▄");
        assert_eq!(m.sparkline(0), "");
        assert_eq!(RateMeter::default().sparkline(5), "");
    }

    #[test]
    fn progress_text_drops_sparkline_then_rate() {
        let m = steady(380, 6);
        let rate = m.rate();
        let full = progress_text(15_840, 25_400, rate, &m, 200);
        assert_eq!(full, "15,840 / 25,400 probes · 380/s ██████");
        let no_spark = "15,840 / 25,400 probes · 380/s";
        let counts = "15,840 / 25,400 probes";
        let w = |t: &str| t.chars().count() + 1 + MIN_BAR;
        assert_eq!(
            progress_text(15_840, 25_400, rate, &m, w(&full) - 1),
            no_spark
        );
        assert_eq!(
            progress_text(15_840, 25_400, rate, &m, w(no_spark) - 1),
            counts
        );
        assert_eq!(progress_text(15_840, 25_400, rate, &m, w(counts) - 1), "");
        assert_eq!(progress_text(15_840, 25_400, None, &m, 200), counts);
        assert_eq!(progress_text(0, 0, None, &RateMeter::default(), 0), "");
    }
}
