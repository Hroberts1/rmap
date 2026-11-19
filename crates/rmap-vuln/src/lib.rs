//! Vulnerability matching: offline CPE -> CVE lookup against a local
//! SQLite database file (see [`SCHEMA_SQL`] and [`default_path`]).
//!
//! A match is reported as **potentially** vulnerable, never certain: a
//! vendor backport can fix the real bug while leaving the version string
//! unchanged, and a version the database has no data for is not evidence
//! of safety.
//!
//! [`update`] downloads a new database file and installs it safely;
//! [`PartFile`] is the temporary-file-then-rename step it shares with the
//! NVD builder (`rmap-nvd`).

mod db;
mod sha256;
mod update;
pub mod version;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};

pub use db::{Bound, CpeMatch, DbError, Entry, SCHEMA_SQL, SCHEMA_VERSION, Writer};
pub use rmap_core::{VulnSeverity, Vulnerability};
pub use update::{
    DEFAULT_MANIFEST_URL, MAX_DB_BYTES, Manifest, PartFile, Progress, UpdateError, check_url,
    fetch_manifest, install, update,
};

/// What [`Database::find`] returns per matching CVE.
pub type Finding = Vulnerability;

/// About a database file, read when it is opened. Text is cleaned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbInfo {
    pub schema_version: u32,
    /// RFC 3339 UTC, e.g. `2026-11-01T00:00:00Z`; empty if not recorded.
    pub built_at: String,
    /// Where the data came from, e.g. `NVD API 2.0 + CISA KEV`.
    pub source: String,
    pub cve_count: u64,
}

/// An open, read-only vulnerability database.
pub struct Database {
    // A Mutex so one Database can be shared across scan tasks
    // (`Connection` is `Send` but not `Sync`).
    conn: Mutex<Connection>,
    info: DbInfo,
}

impl Database {
    /// Opens `path` read-only and checks its schema version. A missing,
    /// empty, corrupt or non-SQLite file is an error, never a panic.
    pub fn open(path: &Path) -> Result<Database, DbError> {
        match std::fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(DbError::NotFound),
            Err(e) => return Err(db::invalid(e)),
            Ok(m) if !m.is_file() => return Err(db::invalid("not a file")),
            Ok(_) => {}
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags).map_err(db::invalid)?;
        // The file comes from the internet: don't let its schema run
        // functions with side effects, and refuse to follow corrupt pages.
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
            .and_then(|_| conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true))
            .map_err(db::invalid)?;
        // Real tables only: a view in their place could run arbitrary SQL.
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN ('meta', 'cve', 'cpe_match')",
                [],
                |r| r.get(0),
            )
            .map_err(db::invalid)?;
        if tables != 3 {
            return Err(db::invalid("missing tables"));
        }
        let version = db::meta(&conn, "schema_version").map_err(db::invalid)?;
        if version.as_deref().and_then(|v| v.parse().ok()) != Some(SCHEMA_VERSION) {
            let found = version.map_or("none".to_string(), |v| db::clean_meta(Some(v)));
            return Err(db::invalid(format!(
                "schema version {found}, rmap reads {SCHEMA_VERSION}"
            )));
        }
        let meta = |key| db::meta(&conn, key).map_err(db::invalid);
        let info = DbInfo {
            schema_version: SCHEMA_VERSION,
            built_at: db::clean_meta(meta("built_at")?),
            source: db::clean_meta(meta("source")?),
            cve_count: meta("cve_count")?.and_then(|v| v.parse().ok()).unwrap_or(0),
        };
        Ok(Database {
            conn: Mutex::new(conn),
            info,
        })
    }

    pub fn info(&self) -> &DbInfo {
        &self.info
    }

    /// Any `meta` value, cleaned and capped like the others; `None` when
    /// absent or unreadable.
    pub fn meta(&self, key: &str) -> Option<String> {
        db::meta(&self.conn(), key)
            .ok()
            .flatten()
            .map(|v| db::clean_meta(Some(v)))
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Findings whose match criteria cover this CPE 2.3 string, one per
    /// CVE, newest first. An unparseable CPE (not rmap's own output), or a
    /// read error in a damaged file, matches nothing.
    pub fn find(&self, cpe: &str) -> Vec<Finding> {
        let Some(parsed) = ParsedCpe::parse(cpe) else {
            return Vec::new();
        };
        // An unknown version (`*`, `-` or empty) can't be checked: `*`
        // sorts below every number, so it would match every "before X"
        // range and flood the result with false findings. Callers report
        // such ports as "version hidden" instead.
        if matches!(parsed.effective_version.as_str(), "" | "*" | "-") {
            return Vec::new();
        }
        db::find(&self.conn(), &parsed).unwrap_or_default()
    }

    /// Whether the database has any data for this product, so "no
    /// findings" can be told apart from "nothing known".
    pub fn knows_product(&self, vendor: &str, product: &str) -> bool {
        self.conn()
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM cpe_match WHERE vendor = ?1 AND product = ?2)",
                [vendor.to_ascii_lowercase(), product.to_ascii_lowercase()],
                |r| r.get(0),
            )
            .unwrap_or(false)
    }
}

/// Where rmap keeps its vulnerability database: `vulns.db` in the
/// platform's data directory (`%LOCALAPPDATA%\rmap` on Windows,
/// `~/Library/Application Support/rmap` on macOS, `$XDG_DATA_HOME/rmap`
/// or `~/.local/share/rmap` elsewhere). `None` when none can be found.
// Same lookup as rmap-report's `store::data_dir`, copied so this crate
// depends only on rmap-core; keep the two in step.
pub fn default_path() -> Option<PathBuf> {
    let env = |k| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let dir = if cfg!(windows) {
        env("LOCALAPPDATA").map(|p| p.join("rmap"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|p| p.join("Library/Application Support/rmap"))
    } else {
        env("XDG_DATA_HOME")
            .map(|p| p.join("rmap"))
            .or_else(|| env("HOME").map(|p| p.join(".local/share/rmap")))
    };
    dir.map(|d| d.join("vulns.db"))
}

/// The fields of a CPE 2.3 string that matching needs. rmap only ever
/// matches its own generated CPEs (see `rmap-detect`'s `cpe.rs`), which
/// contain no internal colons, so this is a plain split - not a general
/// CPE 2.3 unescaper.
pub(crate) struct ParsedCpe<'a> {
    pub vendor: &'a str,
    pub product: &'a str,
    /// Version and update combined the way range bounds are written
    /// (`version` "9.7", `update` "p1" -> `"9.7p1"`); see `version.rs`.
    pub effective_version: String,
}

impl<'a> ParsedCpe<'a> {
    pub(crate) fn parse(cpe: &'a str) -> Option<ParsedCpe<'a>> {
        let fields: Vec<&str> = cpe.split(':').collect();
        // cpe : 2.3 : part : vendor : product : version : update : ...
        let (vendor, product, version, update) = (
            fields.get(3)?,
            fields.get(4)?,
            fields.get(5)?,
            fields.get(6)?,
        );
        let mut effective_version = (*version).to_string();
        if *update != "*" && !update.is_empty() {
            effective_version.push_str(update);
        }
        Some(ParsedCpe {
            vendor,
            product,
            effective_version,
        })
    }
}

#[cfg(test)]
mod tests;
