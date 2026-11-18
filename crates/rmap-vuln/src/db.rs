//! The vulnerability database: a text file in an rmap-specific format,
//! embedded in the binary (`cves.txt`) and parsed once at startup.
//!
//! ```text
//! # Comments start with `#`. Indentation is for readability only.
//! cve CVE-2024-6387
//!   match    openbsd openssh >= 8.5p1 <= 9.7p1   # 1-2 bound tokens, or none for "any version"
//!   severity high                                 # low | medium | high | critical
//!   score    8.1                                  # optional CVSS base score, 0.0-10.0
//!   published 2024-07-01                           # optional, YYYY-MM-DD
//!   summary  "regreSSHion: signal handler race condition, unauthenticated RCE"
//! ```
//!
//! * A `cve` block takes one or more `match` lines (checked against the
//!   vendor/product/version `rmap-detect`'s `cpe.rs` produces), then its
//!   `severity`, optional `score` and `published`, and a quoted `summary`.
//! * A `match` line's bound tokens are `<`, `<=`, `>`, `>=` or `==`,
//!   each followed by a version. Two tokens give a range; one gives a
//!   single-sided bound or an exact version (`==`); none matches any
//!   version of that vendor/product.
//! * `summary` is a quoted string; `\"` and `\\` are the only escapes.

use std::fmt;

use crate::ParsedCpe;
use crate::version::compare;
use rmap_core::{VulnSeverity, Vulnerability};
use std::cmp::Ordering;

/// The database shipped with rmap.
pub const BUILTIN: &str = include_str!("cves.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for DbError {}

fn parse_severity(s: &str) -> Option<VulnSeverity> {
    Some(match s {
        "low" => VulnSeverity::Low,
        "medium" => VulnSeverity::Medium,
        "high" => VulnSeverity::High,
        "critical" => VulnSeverity::Critical,
        _ => return None,
    })
}

/// One side of a version range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    Including(String),
    Excluding(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeMatch {
    pub vendor: String,
    pub product: String,
    pub min: Option<Bound>,
    pub max: Option<Bound>,
}

impl CpeMatch {
    pub(crate) fn matches(&self, cpe: &ParsedCpe) -> bool {
        if !self.vendor.eq_ignore_ascii_case(cpe.vendor)
            || !self.product.eq_ignore_ascii_case(cpe.product)
        {
            return false;
        }
        let v = cpe.effective_version.as_str();
        let min_ok = match &self.min {
            None => true,
            Some(Bound::Including(b)) => compare(v, b) != Ordering::Less,
            Some(Bound::Excluding(b)) => compare(v, b) == Ordering::Greater,
        };
        let max_ok = match &self.max {
            None => true,
            Some(Bound::Including(b)) => compare(v, b) != Ordering::Greater,
            Some(Bound::Excluding(b)) => compare(v, b) == Ordering::Less,
        };
        min_ok && max_ok
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub finding: Vulnerability,
    pub matches: Vec<CpeMatch>,
}

struct Lines<'a> {
    rest: std::str::Lines<'a>,
    n: usize,
}

impl<'a> Lines<'a> {
    fn new(text: &'a str) -> Self {
        Lines {
            rest: text.lines(),
            n: 0,
        }
    }
}

impl<'a> Iterator for Lines<'a> {
    /// `(line_number, keyword, rest_of_line)`; comment and blank lines are
    /// skipped before yielding.
    type Item = (usize, &'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let raw = self.rest.next()?;
            self.n += 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (keyword, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            return Some((self.n, keyword, value.trim()));
        }
    }
}

fn err(line: usize, message: impl Into<String>) -> DbError {
    DbError {
        line,
        message: message.into(),
    }
}

fn parse_quoted(line: usize, s: &str) -> Result<String, DbError> {
    let inner = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| err(line, "summary must be a quoted string"))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// A `match` line's bound tokens: zero, or 1-2 `<op> <version>` pairs.
fn parse_bounds(line: usize, tokens: &[&str]) -> Result<(Option<Bound>, Option<Bound>), DbError> {
    let mut min = None;
    let mut max = None;
    let mut i = 0;
    while i < tokens.len() {
        let Some(op) = tokens.get(i) else { break };
        let Some(version) = tokens.get(i + 1) else {
            return Err(err(line, format!("`{op}` needs a version after it")));
        };
        let version = version.to_string();
        match *op {
            "<" => max = Some(Bound::Excluding(version)),
            "<=" => max = Some(Bound::Including(version)),
            ">" => min = Some(Bound::Excluding(version)),
            ">=" => min = Some(Bound::Including(version)),
            "==" => {
                min = Some(Bound::Including(version.clone()));
                max = Some(Bound::Including(version));
            }
            other => return Err(err(line, format!("unknown bound operator `{other}`"))),
        }
        i += 2;
    }
    Ok((min, max))
}

pub fn parse(text: &str) -> Result<Vec<Entry>, DbError> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut lines = Lines::new(text).peekable();

    while let Some((line, keyword, value)) = lines.next() {
        if keyword != "cve" {
            return Err(err(line, format!("expected `cve`, found `{keyword}`")));
        }
        let id = value.trim();
        if id.is_empty() {
            return Err(err(line, "cve needs an id"));
        }
        let mut matches = Vec::new();
        let mut severity = None;
        let mut score = None;
        let mut published = None;
        let mut summary = None;

        while let Some(&(l, kw, v)) = lines.peek() {
            if kw == "cve" {
                break;
            }
            lines.next();
            match kw {
                "match" => {
                    let tokens: Vec<&str> = v.split_whitespace().collect();
                    if tokens.len() < 2 {
                        return Err(err(l, "match needs a vendor and a product"));
                    }
                    let (min, max) = parse_bounds(l, &tokens[2..])?;
                    matches.push(CpeMatch {
                        vendor: tokens[0].to_string(),
                        product: tokens[1].to_string(),
                        min,
                        max,
                    });
                }
                "severity" => {
                    severity = Some(parse_severity(v).ok_or_else(|| {
                        err(
                            l,
                            format!("unknown severity `{v}` (want low, medium, high or critical)"),
                        )
                    })?);
                }
                "score" => {
                    let parsed: f32 = v
                        .parse()
                        .map_err(|_| err(l, format!("`{v}` is not a number")))?;
                    if !(0.0..=10.0).contains(&parsed) {
                        return Err(err(l, format!("score {parsed} is outside 0.0-10.0")));
                    }
                    score = Some(parsed);
                }
                "published" => {
                    let valid = v.len() == 10
                        && v.as_bytes().get(4) == Some(&b'-')
                        && v.as_bytes().get(7) == Some(&b'-')
                        && v.bytes()
                            .enumerate()
                            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
                    if !valid {
                        return Err(err(l, format!("`{v}` is not a YYYY-MM-DD date")));
                    }
                    published = Some(v.to_string());
                }
                "summary" => summary = Some(parse_quoted(l, v)?),
                other => return Err(err(l, format!("unknown field `{other}`"))),
            }
        }

        if matches.is_empty() {
            return Err(err(line, format!("{id} has no match lines")));
        }
        let severity = severity.ok_or_else(|| err(line, format!("{id} has no severity")))?;
        let summary = summary.ok_or_else(|| err(line, format!("{id} has no summary")))?;

        entries.push(Entry {
            finding: Vulnerability {
                id: id.to_string(),
                summary,
                severity,
                score,
                published,
            },
            matches,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_database_parses_without_error() {
        let entries = parse(BUILTIN).unwrap_or_else(|e| panic!("cves.txt {e}"));
        assert!(!entries.is_empty());
        for entry in &entries {
            assert!(entry.finding.id.starts_with("CVE-"), "{}", entry.finding.id);
            assert!(
                !entry.matches.is_empty(),
                "{} has no match lines",
                entry.finding.id
            );
        }
    }

    #[test]
    fn a_range_with_both_bounds_parses_correctly() {
        let entries = parse(
            r#"
cve CVE-2024-6387
  match    openbsd openssh >= 8.5p1 <= 9.7p1
  severity high
  score    8.1
  published 2024-07-01
  summary  "regreSSHion"
"#,
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        let m = &entries[0].matches[0];
        assert_eq!(m.min, Some(Bound::Including("8.5p1".into())));
        assert_eq!(m.max, Some(Bound::Including("9.7p1".into())));
        assert_eq!(entries[0].finding.score, Some(8.1));
        assert_eq!(entries[0].finding.published.as_deref(), Some("2024-07-01"));
    }

    #[test]
    fn an_exact_match_sets_both_bounds_to_the_same_version() {
        let entries = parse(
            r#"
cve CVE-2021-41773
  match    apache http_server == 2.4.49
  severity critical
  summary  "path traversal"
"#,
        )
        .unwrap();
        let m = &entries[0].matches[0];
        assert_eq!(m.min, Some(Bound::Including("2.4.49".into())));
        assert_eq!(m.max, Some(Bound::Including("2.4.49".into())));
    }

    #[test]
    fn no_bound_tokens_matches_any_version() {
        let entries = parse(
            r#"
cve CVE-2022-0543
  match    redis redis
  severity critical
  summary  "distro-specific Lua sandbox escape"
"#,
        )
        .unwrap();
        let m = &entries[0].matches[0];
        assert_eq!(m.min, None);
        assert_eq!(m.max, None);
    }

    #[test]
    fn multiple_match_lines_on_one_cve_are_all_kept() {
        let entries = parse(
            r#"
cve CVE-2012-2122
  match    oracle mysql < 5.1.63
  match    mariadb mariadb < 5.1.62
  severity medium
  summary  "auth bypass"
"#,
        )
        .unwrap();
        assert_eq!(entries[0].matches.len(), 2);
        assert_eq!(entries[0].matches[1].vendor, "mariadb");
    }

    #[test]
    fn missing_severity_or_summary_or_match_is_an_error() {
        assert!(parse("cve CVE-1\n  summary \"x\"\n  match a b\n").is_err()); // no severity
        assert!(parse("cve CVE-1\n  severity low\n  match a b\n").is_err()); // no summary
        assert!(parse("cve CVE-1\n  severity low\n  summary \"x\"\n").is_err()); // no match
    }

    #[test]
    fn unknown_field_names_and_bad_values_are_rejected_with_a_line_number() {
        let e = parse("cve CVE-1\n  match a b\n  severity low\n  summary \"x\"\n  bogus field\n")
            .unwrap_err();
        assert_eq!(e.line, 5);

        let e = parse("cve CVE-1\n  match a b\n  severity noodle\n  summary \"x\"\n").unwrap_err();
        assert_eq!(e.line, 3);

        let e = parse("cve CVE-1\n  match a b\n  severity low\n  score 11\n  summary \"x\"\n")
            .unwrap_err();
        assert_eq!(e.line, 4);

        let e = parse(
            "cve CVE-1\n  match a b\n  severity low\n  published not-a-date\n  summary \"x\"\n",
        )
        .unwrap_err();
        assert_eq!(e.line, 4);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let entries = parse(
            "# a comment\n\ncve CVE-1\n  # also a comment\n  match a b\n\n  severity low\n  summary \"x\"\n",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut seed: u64 = 0xBADF00D;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet: &[u8] =
            b"cve match severity score published summary \"'<>=.0123456789\n \t#CVElow";
        for _ in 0..50_000 {
            let len = (next() % 200) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize] as char)
                .collect();
            let _ = parse(&s);
        }
    }
}
