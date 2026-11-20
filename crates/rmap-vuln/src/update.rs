//! Downloading a new vulnerability database and installing it safely.
//!
//! A manifest (`vulns.json`) names the database file, its size and its
//! SHA-256. The file is streamed to `<dest>.part` next to `dest`, checked
//! (size, hash, opens as a valid database that agrees with the manifest)
//! and only then renamed over `dest`. Any failure removes the `.part` file
//! and leaves the existing database alone.
//!
//! Blocking: run it on a background thread. Nothing here runs unless the
//! user asks for an update.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use serde::Deserialize;
use ureq::Agent;

use rmap_core::sha256::Sha256;
use crate::{Database, DbError, DbInfo, SCHEMA_VERSION};

/// The project's manifest on GitHub Pages. Its `db` points at that
/// month's immutable `vulndb-YYYY-MM-DD` release (see vulndb.yml).
pub const DEFAULT_MANIFEST_URL: &str = "https://hroberts1.github.io/rmap/vulns.json";

/// The default before the data moved to immutable monthly releases. That
/// release can never be filled again, so saved settings still naming it
/// are moved to [`DEFAULT_MANIFEST_URL`].
pub const OLD_DEFAULT_MANIFEST_URL: &str =
    "https://github.com/Hroberts1/rmap/releases/download/vulndb/vulns.json";

/// Largest database rmap will download.
pub const MAX_DB_BYTES: u64 = 512 * 1024 * 1024;

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_URL_LEN: usize = 2048;
const MAX_REDIRECTS: u32 = 5;
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Ceiling for the whole database download; stalls are caught sooner by
/// the per-read timeout.
const DB_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// A validated `vulns.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub schema_version: u32,
    pub built_at: String,
    pub cve_count: u64,
    pub source: String,
    pub size: u64,
    pub sha256: [u8; 32],
    /// Absolute URL of the database file, already checked by the URL rules.
    pub db_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Manifest,
    Downloading { done: u64, total: u64 },
    Verifying,
    Installing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// Connecting, TLS, timeouts, or the connection dropping.
    Network(String),
    /// The server answered with this HTTP status.
    Http(u16),
    /// A URL (given, or from a manifest or redirect) that rmap won't fetch.
    Insecure(String),
    BadManifest(String),
    /// The manifest's schema version is newer than this rmap reads.
    TooNewSchema(u32),
    /// The manifest's size is over [`MAX_DB_BYTES`].
    TooLarge(u64),
    /// The download wasn't the size the manifest gave.
    SizeMismatch,
    HashMismatch,
    /// The download isn't a database this rmap can use.
    InvalidDb(DbError),
    /// The installed database is open elsewhere (Windows), so it can't be
    /// replaced.
    InUse,
    Io(String),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Network(m) => write!(f, "download failed: {m}"),
            UpdateError::Http(code) => write!(f, "the server answered HTTP {code}"),
            UpdateError::Insecure(m) => write!(f, "refused URL: {m}"),
            UpdateError::BadManifest(m) => write!(f, "invalid update manifest: {m}"),
            UpdateError::TooNewSchema(v) => write!(
                f,
                "the new vulnerability data uses format {v}, this rmap reads format \
                 {SCHEMA_VERSION}: this rmap is too old for the new data; update rmap"
            ),
            UpdateError::TooLarge(n) => write!(
                f,
                "the vulnerability database is {n} bytes, over the {MAX_DB_BYTES} byte limit"
            ),
            UpdateError::SizeMismatch => {
                write!(f, "the download was not the size the manifest promised")
            }
            UpdateError::HashMismatch => {
                write!(f, "the download's SHA-256 does not match the manifest")
            }
            UpdateError::InvalidDb(e) => write!(f, "downloaded file rejected: {e}"),
            UpdateError::InUse => write!(
                f,
                "the vulnerability database is in use or not writable; close running scans \
                 and try again"
            ),
            UpdateError::Io(m) => write!(f, "could not save the vulnerability database: {m}"),
        }
    }
}

impl std::error::Error for UpdateError {}

fn io_err(e: impl fmt::Display) -> UpdateError {
    UpdateError::Io(e.to_string())
}

fn net_err(e: impl fmt::Display) -> UpdateError {
    UpdateError::Network(e.to_string())
}

fn bad(m: impl Into<String>) -> UpdateError {
    UpdateError::BadManifest(m.into())
}

/// Downloads and installs the database the manifest at `url` describes.
pub fn update(
    url: &str,
    dest: &Path,
    progress: &mut dyn FnMut(Progress),
) -> Result<DbInfo, UpdateError> {
    progress(Progress::Manifest);
    let manifest = fetch_manifest(url)?;
    install(&manifest, dest, progress)
}

/// Fetches and validates the manifest at `url`.
pub fn fetch_manifest(url: &str) -> Result<Manifest, UpdateError> {
    let shown = url.split(['?', '#']).next().unwrap_or_default();
    rmap_log::info!("fetching vulnerability database manifest from {shown}");
    let mut body = Vec::new();
    get(&agent(), url, MANIFEST_TIMEOUT)?
        .into_reader()
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(net_err)?;
    if body.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(bad("larger than 64 KiB"));
    }
    let manifest = parse_manifest(&body, url)?;
    rmap_log::info!(
        "manifest: built {}, {} CVEs, {} bytes",
        manifest.built_at,
        manifest.cve_count,
        manifest.size
    );
    Ok(manifest)
}

fn parse_manifest(body: &[u8], manifest_url: &str) -> Result<Manifest, UpdateError> {
    // Version first, so a newer format with other fields says "update rmap"
    // rather than "invalid".
    #[derive(Deserialize)]
    struct Version {
        schema_version: u32,
    }
    #[derive(Deserialize)]
    struct Raw {
        built_at: String,
        cve_count: u64,
        source: String,
        size: u64,
        sha256: String,
        db: String,
    }
    let version: Version = serde_json::from_slice(body).map_err(|e| bad(e.to_string()))?;
    match version.schema_version {
        v if v > SCHEMA_VERSION => return Err(UpdateError::TooNewSchema(v)),
        v if v < SCHEMA_VERSION => {
            return Err(bad(format!(
                "schema version {v} is older than this rmap reads ({SCHEMA_VERSION})"
            )));
        }
        _ => {}
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|e| bad(e.to_string()))?;
    // RFC 3339 is plain ASCII; anything else could spoof the terminal.
    if raw.built_at.is_empty()
        || raw.built_at.len() > 64
        || !raw.built_at.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(bad("built_at must be 1-64 printable ASCII characters"));
    }
    if raw.size == 0 {
        return Err(bad("size is 0"));
    }
    if raw.size > MAX_DB_BYTES {
        return Err(UpdateError::TooLarge(raw.size));
    }
    let sha256 = parse_sha256(&raw.sha256).ok_or_else(|| bad("sha256 must be 64 hex digits"))?;
    if raw.db.is_empty() {
        return Err(bad("db is empty"));
    }
    let db_url = resolve(manifest_url, &raw.db);
    check_url(&db_url)?;
    Ok(Manifest {
        schema_version: version.schema_version,
        built_at: raw.built_at,
        cve_count: raw.cve_count,
        source: crate::db::clean_meta(Some(raw.source)),
        size: raw.size,
        sha256,
        db_url,
    })
}

fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Downloads `manifest.db_url`, verifies it and atomically replaces `dest`.
/// On any error `dest` is left as it was and no `.part` file remains.
pub fn install(
    manifest: &Manifest,
    dest: &Path,
    progress: &mut dyn FnMut(Progress),
) -> Result<DbInfo, UpdateError> {
    if manifest.size > MAX_DB_BYTES {
        return Err(UpdateError::TooLarge(manifest.size));
    }
    let part = PartFile::new(dest)?;
    let reader = get(&agent(), &manifest.db_url, DB_TIMEOUT)?.into_reader();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part.path())
        .map_err(io_err)?;

    let hash = download(reader, &mut file, manifest.size, progress)?;
    file.sync_all().map_err(io_err)?;
    drop(file);

    progress(Progress::Verifying);
    if hash != manifest.sha256 {
        return Err(UpdateError::HashMismatch);
    }
    // Closed again before the rename: Windows can't rename an open file.
    let info = Database::open(part.path())
        .map_err(UpdateError::InvalidDb)?
        .info()
        .clone();
    if info.cve_count != manifest.cve_count {
        return Err(UpdateError::InvalidDb(DbError::Invalid(format!(
            "it has {} CVEs, the manifest says {}",
            info.cve_count, manifest.cve_count
        ))));
    }

    progress(Progress::Installing);
    part.install(dest)?;
    rmap_log::info!(
        "installed vulnerability database ({} CVEs, built {}) at {}",
        info.cve_count,
        info.built_at,
        dest.display()
    );
    Ok(info)
}

/// Streams at most `total` bytes into `file`, returning their SHA-256.
fn download(
    reader: impl Read,
    file: &mut File,
    total: u64,
    progress: &mut dyn FnMut(Progress),
) -> Result<[u8; 32], UpdateError> {
    // One byte past `total` is enough to know the body is too long.
    let mut reader = reader.take(total + 1);
    let mut buf = vec![0u8; 64 * 1024];
    let mut sha = Sha256::new();
    let mut done = 0u64;
    progress(Progress::Downloading { done, total });
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(net_err(e)),
        };
        done += n as u64;
        if done > total {
            return Err(UpdateError::SizeMismatch);
        }
        sha.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(io_err)?;
        rmap_log::trace!("downloaded {done}/{total} bytes");
        progress(Progress::Downloading { done, total });
    }
    if done != total {
        return Err(UpdateError::SizeMismatch);
    }
    Ok(sha.finish())
}

/// `<dest>.part`, where a new database is written before it replaces
/// `dest`: removed (with any SQLite side files) when dropped; after
/// [`PartFile::install`] there is nothing left to remove. Holding one also
/// keeps any other update or build in this process off the same path.
pub struct PartFile {
    path: PathBuf,
    _one_at_a_time: MutexGuard<'static, ()>,
}

impl PartFile {
    /// Creates `dest`'s directory if needed and removes a stale `.part`
    /// from an interrupted run; creating the file is left to the caller.
    /// Waits while another `PartFile` is alive in this process.
    pub fn new(dest: &Path) -> Result<PartFile, UpdateError> {
        let name = dest
            .file_name()
            .ok_or_else(|| io_err("the destination has no file name"))?;
        let path = dest.with_file_name(format!("{}.part", name.to_string_lossy()));
        if let Some(dir) = dest.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(io_err)?;
        }
        // shortcut: another rmap process updating the same file at the same
        // moment is not guarded; add a lock file if that ever happens.
        static INSTALLING: Mutex<()> = Mutex::new(());
        let guard = INSTALLING.lock().unwrap_or_else(|e| e.into_inner());
        match fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_err(e)),
            _ => {}
        }
        Ok(PartFile {
            path,
            _one_at_a_time: guard,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Renames the finished, closed file over `dest` in one step (Windows
    /// can't rename an open file).
    pub fn install(self, dest: &Path) -> Result<(), UpdateError> {
        fs::rename(&self.path, dest).map_err(|e| {
            // Windows: SQLite opens without FILE_SHARE_DELETE, so an open
            // database can't be replaced (access denied / sharing violation).
            if cfg!(windows)
                && (e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(32))
            {
                UpdateError::InUse
            } else {
                io_err(e)
            }
        })
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut side = self.path.clone().into_os_string();
            side.push(suffix);
            let _ = fs::remove_file(side);
        }
    }
}

fn agent() -> Agent {
    Agent::config_builder()
        // Redirects are followed by `get`, so each hop is checked.
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_resolve(Some(Duration::from_secs(15)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_per_read(Some(Duration::from_secs(30)))
        .user_agent(concat!("rmap/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// GETs `url`, following up to [`MAX_REDIRECTS`] redirects, each checked
/// with [`check_url`]. Only a 200 response is accepted.
fn get(agent: &Agent, url: &str, timeout: Duration) -> Result<ureq::Body, UpdateError> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let loopback = check_url(&url)?;
        let mut req = agent.get(&url).config().timeout_global(Some(timeout));
        if loopback {
            // A proxy from the environment never helps reach this computer.
            req = req.proxy(None);
        }
        let resp = req.build().call().map_err(net_err)?;
        let status = resp.status().as_u16();
        match status {
            200 => return Ok(resp.into_body()),
            301 | 302 | 303 | 307 | 308 => {
                let location = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or(UpdateError::Http(status))?;
                url = resolve(&url, location);
                // Redirect targets often carry signed query strings: log the host only.
                rmap_log::debug!("redirected to {}", origin(&url));
            }
            _ => return Err(UpdateError::Http(status)),
        }
    }
    Err(net_err("too many redirects"))
}

/// The pieces of an absolute URL: lowercase scheme, authority, and the
/// rest (path, query, fragment; may be empty).
fn split_url(url: &str) -> Option<(String, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some((scheme.to_ascii_lowercase(), &rest[..end], &rest[end..]))
}

fn origin(url: &str) -> String {
    split_url(url).map_or_else(String::new, |(s, a, _)| format!("{s}://{a}"))
}

/// Whether rmap would fetch `url`: `https://`, or `http://` only to a
/// loopback host. Returns whether the host is loopback. Every URL rmap
/// fetches (given, from a manifest, or a redirect) passes through this.
pub fn check_url(url: &str) -> Result<bool, UpdateError> {
    let insecure = |m: &str| Err(UpdateError::Insecure(m.to_string()));
    if url.len() > MAX_URL_LEN {
        return insecure("too long");
    }
    // Spaces, controls, non-ASCII and backslashes are where URL parsers
    // disagree about the host; none belong in a download URL.
    if !url.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') {
        return insecure("contains spaces, backslashes or non-ASCII characters");
    }
    let Some((scheme, authority, _)) = split_url(url) else {
        return insecure("not an absolute URL");
    };
    if authority.contains('@') {
        return insecure("user names and passwords in URLs are not allowed");
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((h, p)) => (&authority[..h.len() + 2], p),
            None => return insecure("bad IPv6 address"),
        },
        None => authority.split_at(authority.find(':').unwrap_or(authority.len())),
    };
    if host.is_empty() {
        return insecure("no host");
    }
    if !port.is_empty()
        && !port
            .strip_prefix(':')
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return insecure("bad port");
    }
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
        || host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .and_then(|h| h.parse::<Ipv6Addr>().ok())
            .is_some_and(|ip| ip.is_loopback());
    match scheme.as_str() {
        "https" => Ok(loopback),
        "http" if loopback => Ok(true),
        "http" => insecure("plain http is only allowed to this computer; use https"),
        _ => insecure("only https URLs are supported"),
    }
}

/// Resolves `reference` (a manifest's `db`, or a `Location` header)
/// against `base`. The result is checked by [`check_url`] before use.
fn resolve(base: &str, reference: &str) -> String {
    let has_scheme = reference.split_once(':').is_some_and(|(s, _)| {
        s.starts_with(|c: char| c.is_ascii_alphabetic())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    });
    let Some((scheme, authority, rest)) = split_url(base) else {
        return reference.to_string();
    };
    if has_scheme {
        reference.to_string()
    } else if reference.starts_with("//") {
        format!("{scheme}:{reference}")
    } else if reference.starts_with('/') {
        format!("{scheme}://{authority}{reference}")
    } else {
        let path = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
        let dir = &path[..path.rfind('/').map_or(0, |i| i + 1)];
        let dir = if dir.is_empty() { "/" } else { dir };
        format!("{scheme}://{authority}{dir}{reference}")
    }
}

#[cfg(test)]
mod tests;
