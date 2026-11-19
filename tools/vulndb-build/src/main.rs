//! Builds rmap's vulnerability database (`vulns.db`) from the NVD CVE API
//! 2.0 and CISA's Known Exploited Vulnerabilities list, keeping only
//! products rmap can detect. A maintainer tool run by
//! `.github/workflows/vulndb.yml`, not part of the scanner.
//!
//! Configured by environment variables:
//! - `NVD_API_KEY`: optional; raises NVD's rate limit from 5 to 50
//!   requests per 30 s.
//! - `OUT_DIR`: where `vulns.db` and `vulns.meta.json` go (default `.`).
//!   Neither file may exist yet.
//! - `NVD_MAX_PAGES`: stop after this many pages, for a quick trial run.
//!   Also skips the minimum-size check, so never set it when publishing.

mod convert;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmap_vuln::{Entry, SCHEMA_VERSION, Writer};
use serde_json::Value;

const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const SOURCE: &str = "NVD API 2.0 + CISA KEV";
const PAGE_SIZE: u64 = 2000;
/// A full build keeps a few thousand CVEs; fewer means a broken response.
const MIN_CVES: usize = 500;
/// KEV lists well over a thousand CVEs.
const MIN_KEV: usize = 500;
/// Response size caps, so a misbehaving server can't exhaust memory.
const NVD_BODY_LIMIT: u64 = 256 * 1024 * 1024;
const KEV_BODY_LIMIT: u64 = 32 * 1024 * 1024;
const ATTEMPTS: u32 = 5;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vulndb-build: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let env = |k| {
        std::env::var(k)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let key = env("NVD_API_KEY");
    let out_dir = PathBuf::from(env("OUT_DIR").unwrap_or_else(|| ".".into()));
    let max_pages = match env("NVD_MAX_PAGES") {
        Some(v) => Some(
            v.parse::<u64>()
                .map_err(|_| format!("NVD_MAX_PAGES={v:?} is not a number"))?,
        ),
        None => None,
    };
    let db_path = out_dir.join("vulns.db");
    let meta_path = out_dir.join("vulns.meta.json");
    for p in [&db_path, &meta_path] {
        if p.exists() {
            return Err(format!("{} already exists", p.display()));
        }
    }

    let mut client = Client::new(key.is_some());
    eprintln!(
        "NVD API key: {}; out: {}",
        if key.is_some() {
            "set"
        } else {
            "not set (slow rate limit)"
        },
        out_dir.display()
    );

    let kev = convert::kev_dates(&client.get_json(KEV_URL, None, KEV_BODY_LIMIT)?);
    eprintln!("CISA KEV: {} CVEs", kev.len());
    if kev.len() < MIN_KEV {
        return Err(format!("only {} KEV entries; refusing to build", kev.len()));
    }

    let products: convert::Products = rmap_detect::cpe::nvd_products()
        .map(|(v, p)| (v.to_string(), p.to_string()))
        .collect();
    let (entries, last_modified) =
        fetch_nvd(&mut client, key.as_deref(), &products, &kev, max_pages)?;
    let with_kev = entries
        .values()
        .filter(|e| e.finding.kev_added.is_some())
        .count();
    eprintln!("kept {} CVEs ({with_kev} on KEV)", entries.len());
    if entries.len() < MIN_CVES {
        if max_pages.is_none() {
            return Err(format!(
                "only {} CVEs kept; refusing to build",
                entries.len()
            ));
        }
        eprintln!("warning: below {MIN_CVES} CVEs; allowed only because NVD_MAX_PAGES is set");
    }

    let built_at = rfc3339(SystemTime::now());
    write_db(&db_path, &entries, &built_at, last_modified.as_deref()).map_err(|e| {
        // Never leave a half-written file behind for the workflow to upload.
        let _ = std::fs::remove_file(&db_path);
        format!("{}: {e}", db_path.display())
    })?;
    let meta = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "built_at": built_at,
        "cve_count": entries.len(),
        "source": SOURCE,
    });
    std::fs::write(&meta_path, format!("{meta:#}\n"))
        .map_err(|e| format!("{}: {e}", meta_path.display()))?;
    eprintln!("wrote {} and {}", db_path.display(), meta_path.display());
    Ok(())
}

/// Every NVD page, converted and filtered, keyed by CVE id (a CVE that
/// moves between pages mid-sync is kept once), plus the newest
/// `lastModified` seen.
fn fetch_nvd(
    client: &mut Client,
    key: Option<&str>,
    products: &convert::Products,
    kev: &HashMap<String, String>,
    max_pages: Option<u64>,
) -> Result<(BTreeMap<String, Entry>, Option<String>), String> {
    let mut entries = BTreeMap::new();
    let mut last_modified: Option<String> = None;
    let mut start = 0u64;
    let mut page_no = 0u64;
    loop {
        let url = format!("{NVD_URL}?startIndex={start}&resultsPerPage={PAGE_SIZE}");
        let json = client.get_json(&url, key, NVD_BODY_LIMIT)?;
        let page = convert::convert_page(&json, products, kev)
            .ok_or_else(|| format!("startIndex={start}: not an NVD CVE page"))?;
        page_no += 1;
        start += page.returned as u64;
        if page.last_modified > last_modified {
            last_modified = page.last_modified;
        }
        for e in page.entries {
            entries.insert(e.finding.id.clone(), e);
        }
        eprintln!(
            "NVD page {page_no}: {start}/{} CVEs read, {} kept",
            page.total_results,
            entries.len()
        );
        if start >= page.total_results || max_pages.is_some_and(|m| page_no >= m) {
            return Ok((entries, last_modified));
        }
        if page.returned == 0 {
            return Err(format!("NVD returned an empty page at startIndex={start}"));
        }
    }
}

/// Writer keeps SQLite's default rollback journal and `finish` commits and
/// closes, so the file is complete with no `-journal`/`-wal` beside it
/// before the workflow hashes it (rmap opens it read-only).
fn write_db(
    path: &Path,
    entries: &BTreeMap<String, Entry>,
    built_at: &str,
    last_modified: Option<&str>,
) -> Result<(), rmap_vuln::DbError> {
    let mut w = Writer::create(path)?;
    for e in entries.values() {
        w.add(e)?;
    }
    w.set_meta("built_at", built_at)?;
    w.set_meta("source", SOURCE)?;
    if let Some(lm) = last_modified {
        w.set_meta("nvd_last_modified", lm)?;
    }
    w.finish()
}

/// HTTP with NVD's rate limit and retries.
struct Client {
    agent: ureq::Agent,
    /// Gap between requests: NVD allows 5 per 30 s without a key (and asks
    /// for ~6 s between them), 50 per 30 s with one.
    spacing: Duration,
    last: Option<Instant>,
}

impl Client {
    fn new(have_key: bool) -> Client {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_global(Some(Duration::from_secs(300)))
            .user_agent("rmap-vulndb-build")
            .build()
            .into();
        let spacing = Duration::from_secs(if have_key { 1 } else { 6 });
        Client {
            agent,
            spacing,
            last: None,
        }
    }

    /// GETs and parses JSON, retrying rate limiting (403/429), server
    /// errors, network errors and unparseable bodies with backoff.
    fn get_json(&mut self, url: &str, key: Option<&str>, limit: u64) -> Result<Value, String> {
        let mut attempt = 0;
        loop {
            if let Some(last) = self.last {
                sleep(self.spacing.saturating_sub(last.elapsed()));
            }
            self.last = Some(Instant::now());
            attempt += 1;
            let err = match self.get_once(url, key, limit) {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let retry = match &err {
                ureq::Error::StatusCode(code) => matches!(code, 403 | 429 | 500..=599),
                _ => true,
            };
            if !retry || attempt >= ATTEMPTS {
                return Err(format!("GET {url}: {err} (attempt {attempt})"));
            }
            let wait = Duration::from_secs(15 << attempt);
            eprintln!("GET {url}: {err}; retrying in {}s", wait.as_secs());
            sleep(wait);
        }
    }

    fn get_once(&self, url: &str, key: Option<&str>, limit: u64) -> Result<Value, ureq::Error> {
        let mut req = self.agent.get(url);
        if let Some(k) = key {
            req = req.header("apiKey", k);
        }
        let body = req
            .call()?
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()?;
        serde_json::from_slice(&body).map_err(|e| ureq::Error::Io(e.into()))
    }
}

/// `SystemTime` as RFC 3339 UTC to the second, e.g. `2026-11-01T06:17:00Z`.
fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
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
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published file must open read-only: committed, closed, and in
    /// rollback-journal mode with no `-journal`/`-wal` file left beside it.
    #[test]
    fn written_db_is_closed_and_opens_read_only() {
        let dir = std::env::temp_dir().join(format!("vulndb-build-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vulns.db");
        let entry = Entry {
            finding: rmap_core::Vulnerability {
                id: "CVE-2024-6387".into(),
                summary: "x".into(),
                severity: rmap_core::VulnSeverity::High,
                score: Some(8.1),
                published: Some("2024-07-01".into()),
                kev_added: None,
            },
            matches: vec![rmap_vuln::CpeMatch {
                vendor: "openbsd".into(),
                product: "openssh".into(),
                min: None,
                max: Some(rmap_vuln::Bound::Excluding("9.8p1".into())),
            }],
        };
        let entries = BTreeMap::from([(entry.finding.id.clone(), entry)]);
        let written = write_db(&path, &entries, "2026-11-01T06:17:00Z", Some("2026-10-31"));
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let header = std::fs::read(&path).unwrap_or_default();
        let opened = rmap_vuln::Database::open(&path).map(|db| {
            let found = db
                .find("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*")
                .len();
            (db.info().clone(), found)
        });
        let _ = std::fs::remove_dir_all(&dir);
        written.unwrap();
        assert_eq!(leftovers, ["vulns.db"]);
        // File format bytes 18/19: 1 = rollback journal, 2 = WAL.
        assert_eq!((header[18], header[19]), (1, 1));
        let (info, found) = opened.unwrap();
        assert_eq!(info.cve_count, 1);
        assert_eq!(info.source, SOURCE);
        assert_eq!(info.built_at, "2026-11-01T06:17:00Z");
        assert_eq!(found, 1);
    }

    #[test]
    fn rfc3339_formats_utc() {
        let at = |s| rfc3339(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_793_510_225), "2026-11-01T05:17:05Z");
        assert_eq!(at(1_709_251_199), "2024-02-29T23:59:59Z");
    }
}
