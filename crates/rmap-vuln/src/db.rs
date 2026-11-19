//! The vulnerability database file: a SQLite database with the schema in
//! [`SCHEMA_SQL`], read by [`crate::Database`] and written by [`Writer`].
//!
//! The file is downloaded from the internet, so everything read from it
//! is untrusted: rows that don't fit the schema are skipped, never a
//! panic, and text is cleaned before anyone can show it in a terminal.

use std::cmp::Ordering;
use std::fmt;
use std::fs::OpenOptions;
use std::path::Path;

use rusqlite::{Connection, Row, params};

use crate::ParsedCpe;
use crate::version::compare;
use rmap_core::{VulnSeverity, Vulnerability};

pub const SCHEMA_VERSION: u32 = 1;

/// Schema v1. `meta` keys: `schema_version`, `built_at` (RFC 3339 UTC),
/// `source` (free text) and `cve_count`. Versions are stored in the
/// combined form `version.rs` compares (`9.7p1`); SQL only selects rows by
/// vendor and product, and Rust decides range membership.
pub const SCHEMA_SQL: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE cve (
  id TEXT PRIMARY KEY, summary TEXT NOT NULL, severity TEXT NOT NULL,
  score REAL, published TEXT,
  kev_added TEXT
);
CREATE TABLE cpe_match (
  cve_id TEXT NOT NULL REFERENCES cve(id),
  vendor TEXT NOT NULL, product TEXT NOT NULL,
  version_exact TEXT,
  start TEXT, start_incl INTEGER, end TEXT, end_incl INTEGER
);
CREATE INDEX cpe_match_product ON cpe_match (vendor, product);
";

/// Longest CVE id and summary kept from the file, in characters.
const MAX_ID: usize = 64;
const MAX_SUMMARY: usize = 4000;
/// Longest `built_at` / `source` meta value kept, in characters.
const MAX_META: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// Nothing at the path.
    NotFound,
    /// [`Writer::create`] won't overwrite an existing file.
    AlreadyExists,
    /// A file rmap can't use: not SQLite, corrupt, missing tables, or a
    /// different schema version.
    Invalid(String),
    /// Writing a new database failed.
    Write(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::NotFound => write!(f, "file not found"),
            DbError::AlreadyExists => write!(f, "file already exists"),
            DbError::Invalid(m) => write!(f, "not a usable vulnerability database: {m}"),
            DbError::Write(m) => write!(f, "could not write the vulnerability database: {m}"),
        }
    }
}

impl std::error::Error for DbError {}

pub(crate) fn invalid(e: impl fmt::Display) -> DbError {
    DbError::Invalid(e.to_string())
}

fn write_err(e: impl fmt::Display) -> DbError {
    DbError::Write(e.to_string())
}

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

/// One `cpe_match` row. An exact version is `min` and `max` both
/// `Including` the same version; no bounds matches any version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeMatch {
    pub vendor: String,
    pub product: String,
    pub min: Option<Bound>,
    pub max: Option<Bound>,
}

impl CpeMatch {
    /// Whether `version` (combined version + update) is inside this range.
    /// Vendor and product were already matched by the SQL query.
    pub(crate) fn covers(&self, version: &str) -> bool {
        let min_ok = match &self.min {
            None => true,
            Some(Bound::Including(b)) => compare(version, b) != Ordering::Less,
            Some(Bound::Excluding(b)) => compare(version, b) == Ordering::Greater,
        };
        let max_ok = match &self.max {
            None => true,
            Some(Bound::Including(b)) => compare(version, b) != Ordering::Greater,
            Some(Bound::Excluding(b)) => compare(version, b) == Ordering::Less,
        };
        min_ok && max_ok
    }

    fn exact(&self) -> Option<&str> {
        match (&self.min, &self.max) {
            (Some(Bound::Including(a)), Some(Bound::Including(b))) if a == b => Some(a),
            _ => None,
        }
    }
}

/// One CVE: a `cve` row plus its `cpe_match` rows.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub finding: Vulnerability,
    pub matches: Vec<CpeMatch>,
}

/// Text from the file made safe to show: line breaks and tabs become
/// spaces, other control characters and bidirectional overrides (which
/// could drive or reorder a terminal) become U+FFFD, capped at `max`.
pub(crate) fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| match c {
            '\r' | '\n' | '\t' => ' ',
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => '\u{FFFD}',
            c if c.is_control() => '\u{FFFD}',
            c => c,
        })
        .collect()
}

fn is_date(v: &str) -> bool {
    v.len() == 10
        && v.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

/// Columns, in order, that [`read_row`] expects.
const FIND_SQL: &str = "
SELECT c.id, c.summary, c.severity, c.score, c.published, c.kev_added,
       m.version_exact, m.start, m.start_incl, m.end, m.end_incl
FROM cpe_match m JOIN cve c ON c.id = m.cve_id
WHERE m.vendor = ?1 AND m.product = ?2";

/// A `find` row as a finding and its range, or `None` for a row that
/// doesn't fit the schema (wrong types, unknown severity, empty id).
/// Optional fields with bad values are dropped rather than the row.
fn read_row(row: &Row) -> Option<(Vulnerability, CpeMatch)> {
    // Outer None: the column has the wrong type, so skip the row (a bad
    // version must not widen a range to "any version"). Inner None: NULL.
    let col = |i| row.get::<_, Option<String>>(i).ok();
    let id = clean(&col(0)??, MAX_ID);
    if id.trim().is_empty() {
        return None;
    }
    let bound = |v: usize, incl: usize| -> Option<Option<Bound>> {
        let Some(v) = col(v)? else {
            return Some(None);
        };
        // NULL inclusivity counts as inclusive: when unsure, flag it.
        let incl = row.get::<_, Option<i64>>(incl).ok()? != Some(0);
        Some(Some(if incl {
            Bound::Including(v)
        } else {
            Bound::Excluding(v)
        }))
    };
    let (min, max) = match col(6)? {
        Some(v) => (Some(Bound::Including(v.clone())), Some(Bound::Including(v))),
        None => (bound(7, 8)?, bound(9, 10)?),
    };
    let finding = Vulnerability {
        id,
        summary: clean(&col(1)??, MAX_SUMMARY),
        severity: parse_severity(&col(2)??)?,
        score: row
            .get::<_, Option<f64>>(3)
            .ok()
            .flatten()
            .filter(|s| (0.0..=10.0).contains(s))
            .map(|s| s as f32),
        published: col(4).flatten().filter(|d| is_date(d)),
        kev_added: col(5).flatten().filter(|d| is_date(d)),
    };
    // Vendor and product are left empty: the query already matched them.
    let range = CpeMatch {
        vendor: String::new(),
        product: String::new(),
        min,
        max,
    };
    Some((finding, range))
}

/// Matching rows for a parsed CPE: findings whose range covers its
/// version, one per CVE id, newest first.
pub(crate) fn find(conn: &Connection, cpe: &ParsedCpe) -> rusqlite::Result<Vec<Vulnerability>> {
    let mut stmt = conn.prepare_cached(FIND_SQL)?;
    let rows = stmt.query_map(
        params![
            cpe.vendor.to_ascii_lowercase(),
            cpe.product.to_ascii_lowercase()
        ],
        |row| Ok(read_row(row)),
    )?;
    let mut found: Vec<Vulnerability> = rows
        .flatten()
        .flatten()
        .filter(|(_, range)| range.covers(&cpe.effective_version))
        .map(|(finding, _)| finding)
        .collect();
    // Sort-and-dedup rather than a linear search per row: a product can
    // have thousands of rows.
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found.dedup_by(|a, b| a.id == b.id);
    found.sort_by(|a, b| b.published.cmp(&a.published).then(a.id.cmp(&b.id)));
    Ok(found)
}

/// Builds a new database file. Everything goes in one transaction that
/// [`Writer::finish`] commits; dropping a `Writer` without finishing
/// leaves an empty file that [`crate::Database::open`] rejects.
pub struct Writer {
    conn: Connection,
}

impl Writer {
    /// Creates the file and its schema. Fails if the file already exists.
    pub fn create(path: &Path) -> Result<Writer, DbError> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => DbError::AlreadyExists,
                _ => write_err(e),
            })?;
        let conn = Connection::open(path).map_err(write_err)?;
        conn.execute_batch(&format!("BEGIN;{SCHEMA_SQL}"))
            .map_err(write_err)?;
        Ok(Writer { conn })
    }

    /// Adds one CVE. A duplicate id is an error.
    pub fn add(&mut self, entry: &Entry) -> Result<(), DbError> {
        let f = &entry.finding;
        self.conn
            .prepare_cached(
                "INSERT INTO cve (id, summary, severity, score, published, kev_added)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .and_then(|mut s| {
                s.execute(params![
                    f.id,
                    f.summary,
                    f.severity.as_str(),
                    f.score.map(f64::from),
                    f.published,
                    f.kev_added
                ])
            })
            .map_err(write_err)?;
        for m in &entry.matches {
            fn split(b: &Option<Bound>) -> (Option<&str>, Option<i64>) {
                match b {
                    Some(Bound::Including(v)) => (Some(v), Some(1)),
                    Some(Bound::Excluding(v)) => (Some(v), Some(0)),
                    None => (None, None),
                }
            }
            let exact = m.exact();
            let ((start, start_incl), (end, end_incl)) = if exact.is_some() {
                ((None, None), (None, None))
            } else {
                (split(&m.min), split(&m.max))
            };
            self.conn
                .prepare_cached(
                    "INSERT INTO cpe_match (cve_id, vendor, product, version_exact,
                                            start, start_incl, end, end_incl)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .and_then(|mut s| {
                    s.execute(params![
                        f.id,
                        m.vendor.to_ascii_lowercase(),
                        m.product.to_ascii_lowercase(),
                        exact,
                        start,
                        start_incl,
                        end,
                        end_incl
                    ])
                })
                .map_err(write_err)?;
        }
        Ok(())
    }

    /// Sets a `meta` value (`built_at`, `source`, ...). `schema_version`
    /// and `cve_count` are written by [`Writer::finish`].
    pub fn set_meta(&mut self, key: &str, value: &str) -> Result<(), DbError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map(drop)
            .map_err(write_err)
    }

    /// Writes `schema_version` and `cve_count` and commits.
    pub fn finish(mut self) -> Result<(), DbError> {
        let count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM cve", [], |r| r.get(0))
            .map_err(write_err)?;
        self.set_meta("schema_version", &SCHEMA_VERSION.to_string())?;
        self.set_meta("cve_count", &count.to_string())?;
        self.conn.execute_batch("COMMIT").map_err(write_err)
    }
}

/// A `meta` value, `None` when the key is absent.
pub(crate) fn meta(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    match conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
        r.get::<_, String>(0)
    }) {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn clean_meta(v: Option<String>) -> String {
    v.map(|v| clean(&v, MAX_META)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_neutralises_terminal_controls_and_caps_length() {
        assert_eq!(clean("a\x1b[2Jb\u{202E}c", 100), "a\u{FFFD}[2Jb\u{FFFD}c");
        assert_eq!(clean("line\r\nnext\tx", 100), "line  next x");
        assert_eq!(clean("abcdef", 3), "abc");
    }

    #[test]
    fn dates_must_be_yyyy_mm_dd() {
        assert!(is_date("2024-07-01"));
        assert!(!is_date("2024-7-01"));
        assert!(!is_date("2024/07/01"));
        assert!(!is_date("2024-07-011"));
        assert!(!is_date("éé-07-01"));
    }

    #[test]
    fn ranges_respect_inclusive_and_exclusive_bounds() {
        let r = |min, max| CpeMatch {
            vendor: String::new(),
            product: String::new(),
            min,
            max,
        };
        let inc = |v: &str| Some(Bound::Including(v.into()));
        let exc = |v: &str| Some(Bound::Excluding(v.into()));
        assert!(r(inc("1.0"), inc("2.0")).covers("1.0"));
        assert!(r(inc("1.0"), inc("2.0")).covers("2.0"));
        assert!(!r(exc("1.0"), exc("2.0")).covers("1.0"));
        assert!(!r(exc("1.0"), exc("2.0")).covers("2.0"));
        assert!(r(exc("1.0"), exc("2.0")).covers("1.5"));
        assert!(r(None, None).covers("anything"));
        assert_eq!(r(inc("2.4.49"), inc("2.4.49")).exact(), Some("2.4.49"));
        assert_eq!(r(inc("1"), inc("2")).exact(), None);
    }
}
