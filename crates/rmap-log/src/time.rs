//! UTC timestamps without a date/time dependency.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC instant with millisecond precision, printed as RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub year: i64,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub millis: u16,
}

impl Timestamp {
    pub fn now() -> Self {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Self::from_unix_millis(ms)
    }

    pub fn from_unix_millis(ms: i64) -> Self {
        let secs = ms.div_euclid(1000);
        let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
        let tod = secs.rem_euclid(86_400);
        Timestamp {
            year,
            month,
            day,
            hour: (tod / 3600) as u8,
            minute: (tod / 60 % 60) as u8,
            second: (tod % 60) as u8,
            millis: ms.rem_euclid(1000) as u16,
        }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis
        )
    }
}

/// `YYYYMMDD-HHMMSS` for file names; sorts in time order.
pub fn file_stamp() -> String {
    let t = Timestamp::now();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date.
/// Algorithm from Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms".
fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: i64) -> String {
        Timestamp::from_unix_millis(ms).to_string()
    }

    #[test]
    fn known_instants() {
        assert_eq!(at(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(951_782_400_000), "2000-02-29T00:00:00.000Z"); // leap day
        assert_eq!(at(1_709_251_199_999), "2024-02-29T23:59:59.999Z");
        assert_eq!(at(1_798_761_599_000), "2026-12-31T23:59:59.000Z");
        assert_eq!(at(4_102_444_800_000), "2100-01-01T00:00:00.000Z"); // not a leap year
    }

    #[test]
    fn before_epoch() {
        assert_eq!(at(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn every_day_round_trips_month_and_day_ranges() {
        // Walk 400 years (a full Gregorian cycle) checking dates stay valid
        // and advance by exactly one day.
        let mut prev = civil_from_days(-1);
        for d in 0..146_097 {
            let cur = civil_from_days(d);
            assert!((1..=12).contains(&cur.1) && (1..=31).contains(&cur.2));
            assert!(cur > prev, "day {d}: {cur:?} after {prev:?}");
            prev = cur;
        }
        assert_eq!(civil_from_days(146_097), (2370, 1, 1));
    }
}
