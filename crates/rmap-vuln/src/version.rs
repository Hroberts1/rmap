//! Version comparison for CPE version strings.
//!
//! CVE version ranges are written against the combined `version` + `update`
//! a CPE carries (`openbsd:openssh:9.7:p1` is written as `9.7p1`), so
//! comparison works on that combined string, not on dotted-numeric versions
//! alone. The algorithm is the same one dpkg/rpm use: split into
//! alternating runs of digits and non-digits, compare digit runs
//! numerically and non-digit runs as plain text, and treat a run the other
//! side doesn't have as smaller - so `"9.7"` sorts before `"9.7p1"`, and
//! `"9.7p1"` before `"9.7p2"`.

use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part<'a> {
    Digits(u64),
    Text(&'a str),
}

/// Splits into alternating digit and non-digit runs. Never panics; an
/// absurdly long digit run saturates rather than overflowing.
fn parts(v: &str) -> Vec<Part<'_>> {
    let bytes = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let digit = bytes[i].is_ascii_digit();
        while i < bytes.len() && bytes[i].is_ascii_digit() == digit {
            i += 1;
        }
        let run = &v[start..i];
        out.push(if digit {
            Part::Digits(run.parse().unwrap_or(u64::MAX))
        } else {
            Part::Text(run)
        });
    }
    out
}

/// Compares two version strings. Case-insensitive on the text runs, so
/// `"9.6"` and `"9.6"` compare equal regardless of how an update suffix's
/// case was written. A side that runs out of parts first is smaller,
/// matching how `"9.7"` (a plain release) sorts before `"9.7p1"` (a patch
/// release on top of it).
pub fn compare(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (parts(a), parts(b));
    for (x, y) in pa.iter().zip(pb.iter()) {
        let ord = match (x, y) {
            (Part::Digits(x), Part::Digits(y)) => x.cmp(y),
            (Part::Text(x), Part::Text(y)) => x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()),
            // A digit run and a text run at the same position (uncommon -
            // only when one version has a letter where the other has a
            // separator, e.g. different punctuation): text sorts first, an
            // arbitrary but total and stable order.
            (Part::Digits(_), Part::Text(_)) => Ordering::Greater,
            (Part::Text(_), Part::Digits(_)) => Ordering::Less,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    pa.len().cmp(&pb.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lt(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Less, "{a} should be < {b}");
        assert_eq!(compare(b, a), Ordering::Greater, "{b} should be > {a}");
    }

    fn eq(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Equal, "{a} should == {b}");
    }

    #[test]
    fn dotted_numeric_versions_compare_by_segment() {
        lt("8.9", "9.6");
        lt("1.3.9", "1.4.0");
        lt("2.4.17", "2.4.49");
        lt("4.87", "4.91");
        lt("5.1.9", "5.1.10"); // numeric, not lexical: 10 > 9
    }

    #[test]
    fn a_patch_suffix_sorts_after_the_plain_release_it_patches() {
        lt("9.7", "9.7p1");
        lt("9.7p1", "9.7p2");
        lt("9.7p9", "9.7p10");
    }

    #[test]
    fn equal_strings_and_equal_values_compare_equal() {
        eq("2.3.4", "2.3.4");
        eq("1.3.5", "1.3.5");
        eq("abc", "ABC");
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut seed: u64 = 0xC0FFEE;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet: &[u8] = b"0123456789.pP-+ \t";
        for _ in 0..100_000 {
            let make = |next: &mut dyn FnMut() -> u64| {
                let len = (next() % 12) as usize;
                (0..len)
                    .map(|_| alphabet[(next() % alphabet.len() as u64) as usize] as char)
                    .collect::<String>()
            };
            let (a, b) = (make(&mut next), make(&mut next));
            let _ = compare(&a, &b);
        }
    }
}
