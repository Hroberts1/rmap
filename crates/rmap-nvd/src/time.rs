//! The few UTC date-time conversions the builder needs: `built_at`, NVD's
//! `lastModified` watermark, and the `lastModStartDate`/`lastModEndDate`
//! query parameters. Seconds since the Unix epoch throughout.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// RFC 3339 UTC to the second, e.g. `2026-11-01T06:17:00Z`.
pub fn rfc3339(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = fields(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// An NVD API date-time parameter, already URL-encoded:
/// `2026-11-01T06:17:00.000%2B00:00`.
pub fn nvd_param(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = fields(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000%2B00:00")
}

/// `YYYY-MM-DDTHH:MM:SS`, optionally with `.` and 1-9 fraction digits and
/// a trailing `Z` (NVD's `lastModified`, or our `built_at`), read as UTC.
/// Anything else is `None`: the text comes from a file or the network.
pub fn parse(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| part.iter().fold(0, |n, d| n * 10 + i64::from(d - b'0')))
    };
    let seps = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if seps.iter().any(|&(i, c)| b.get(i) != Some(&c)) {
        return None;
    }
    let (y, mo, d) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (h, mi, sec) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if !(1..=9).contains(&n) {
            return None;
        }
        rest = &frac[n..];
    }
    if !matches!(rest, "" | "Z")
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || sec > 60
    {
        return None;
    }
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec;
    u64::try_from(secs).ok()
}

fn fields(secs: u64) -> (i64, i64, i64, u64, u64, u64) {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil_from_days, for days since 1970-01-01.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Hinnant's days_from_civil: days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_793_510_225), "2026-11-01T05:17:05Z");
        assert_eq!(rfc3339(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(nvd_param(1_793_510_225), "2026-11-01T05:17:05.000%2B00:00");
    }

    #[test]
    fn parse_round_trips_and_rejects_junk() {
        for secs in [0, 951_782_400, 1_709_251_199, 1_793_510_225, 4_102_444_800] {
            assert_eq!(parse(&rfc3339(secs)), Some(secs));
        }
        assert_eq!(parse("2026-11-01T05:17:05.123"), Some(1_793_510_225));
        assert_eq!(parse("2026-11-01T05:17:05"), Some(1_793_510_225));
        for bad in [
            "",
            "2026-11-01",
            "2026-11-01T05:17",
            "2026-13-01T05:17:05",
            "2026-11-00T05:17:05",
            "2026-11-01T24:00:00",
            "2026-11-01T05:17:05.",
            "2026-11-01T05:17:05.1234567890",
            "2026-11-01T05:17:05+01:00",
            "2026-11-01T05:17:05Zjunk",
            "2026-11-01 05:17:05",
            "+026-11-01T05:17:05",
            "1969-12-31T23:59:59",
            "2026-11-01T05:17:05.0\u{e9}",
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
