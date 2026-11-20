//! Builds rmap's vulnerability database (`vulns.db`) from the NVD CVE API
//! 2.0 and CISA's Known Exploited Vulnerabilities list, keeping only
//! products rmap can detect. Used by Settings -> "Build from NVD" (with
//! the user's own NVD API key, if any) and by the maintainer tool
//! `tools/vulndb-build`, which publishes the optional prebuilt file.
//!
//! [`build`] does a full sync, or, when the current file records an NVD
//! sync time less than ~4 months old, a refresh that fetches only the CVEs
//! modified since (see [`plan`]). Either way the new file is written to
//! `<dest>.part`, checked, and only then renamed over `dest`; a failure or
//! cancel leaves `dest` untouched and no `.part` behind.
//!
//! Blocking, and slow by design (NVD's rate limits): run it on a
//! background thread. Nothing here runs unless someone asks for a build.

mod convert;
mod time;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rmap_vuln::{Database, DbError, DbInfo, Entry, PartFile, UpdateError, Writer};
use serde_json::Value;

pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// Where people request a free NVD API key.
pub const API_KEY_URL: &str = "https://nvd.nist.gov/developers/request-an-api-key";
/// The notice NVD's terms of use ask products using the API to show.
pub const NVD_NOTICE: &str =
    "This product uses the NVD API but is not endorsed or certified by the NVD.";
/// `meta.source` of the published prebuilt file.
pub const SOURCE: &str = "NVD API 2.0 + CISA KEV";
/// `meta.source` of a file built or refreshed inside rmap.
pub const LOCAL_SOURCE: &str = "NVD API 2.0 + CISA KEV (built locally)";
/// A full build keeps a few thousand CVEs; fewer means a broken response.
pub const MIN_CVES: u64 = 500;

const PAGE_SIZE: u64 = 2000;
/// KEV lists well over a thousand CVEs.
const MIN_KEV: usize = 500;
/// Response size caps, so a misbehaving server can't exhaust memory.
const NVD_BODY_LIMIT: u64 = 256 * 1024 * 1024;
const KEV_BODY_LIMIT: u64 = 32 * 1024 * 1024;
const ATTEMPTS: u32 = 5;
const DAY: u64 = 86_400;
/// NVD allows at most 120 days between `lastModStartDate` and
/// `lastModEndDate`; two days are kept back for the overlap and clocks.
const MAX_REFRESH_AGE: u64 = 118 * DAY;
/// A refresh starts this long before the watermark: re-reading a day of
/// changes is cheap, and it covers CVEs changed while a long full sync
/// ran, NVD's time zone, and a computer clock that is a little off.
const OVERLAP: u64 = DAY;
/// Bump when conversion changes what is stored, so older files get a full
/// rebuild instead of a refresh on top of differently converted rows.
const CONVERT_VERSION: u32 = 1;

/// What to build, and where. [`BuildOptions::new`] fills in NVD's real
/// URLs and rate limits; tests point the URLs at a loopback server.
// No Debug: it holds the API key.
pub struct BuildOptions {
    /// The database to replace, e.g. `rmap_vuln::default_path()`.
    pub dest: PathBuf,
    /// Sent only as NVD's `apiKey` request header, never in a URL or log.
    pub api_key: Option<String>,
    /// `meta.source` for the new file.
    pub source: String,
    /// Refresh the current file when [`plan`] allows; `false` always
    /// does a full build.
    pub allow_refresh: bool,
    /// Stop after this many NVD pages (a trial run); also skips the
    /// [`MIN_CVES`] check, so never set it for real data.
    pub max_pages: Option<u64>,
    pub nvd_url: String,
    pub kev_url: String,
    /// Least time between two requests.
    pub spacing: Duration,
    /// First retry wait; it doubles each attempt.
    pub backoff: Duration,
}

impl BuildOptions {
    pub fn new(dest: PathBuf, api_key: Option<String>) -> BuildOptions {
        // NVD allows 5 requests per 30 s without a key (and asks for ~6 s
        // between them), 50 per 30 s with one.
        let spacing = Duration::from_secs(if api_key.is_some() { 1 } else { 6 });
        BuildOptions {
            dest,
            api_key,
            source: LOCAL_SOURCE.into(),
            allow_refresh: true,
            max_pages: None,
            nvd_url: NVD_URL.into(),
            kev_url: KEV_URL.into(),
            spacing,
            backoff: Duration::from_secs(15),
        }
    }
}

/// Whether [`build`] would sync everything or refresh the current file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Why a full build is needed, for showing to the user.
    Full(String),
    /// Fetch only CVEs modified since `watermark` (Unix seconds), the
    /// current file's newest NVD `lastModified`, `age_days` ago.
    Refresh { watermark: u64, age_days: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BuildProgress {
    /// Downloading the CISA KEV list.
    Kev,
    /// CVE records read from NVD so far, of `total`, and a rough time
    /// left once a page has come back.
    Nvd {
        read: u64,
        total: u64,
        eta: Option<Duration>,
    },
    /// Rate limited or a server error: waiting before trying again.
    Retrying {
        wait: Duration,
    },
    Writing,
    Verifying,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    Cancelled,
    /// Network errors, refused URLs, and HTTP errors after the retries.
    Network(String),
    /// A response that isn't what NVD or CISA send.
    BadData(String),
    /// The finished file has fewer than [`MIN_CVES`] CVEs.
    TooFew(u64),
    /// The current database is open elsewhere (Windows).
    InUse,
    Io(String),
    Db(DbError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Cancelled => write!(f, "cancelled; the current CVE data was not changed"),
            BuildError::Network(m) => write!(f, "{m}"),
            BuildError::BadData(m) => write!(f, "unexpected response: {m}"),
            BuildError::TooFew(n) => write!(
                f,
                "only {n} CVEs kept, fewer than the {MIN_CVES} a complete database has; \
                 refusing to replace the current data"
            ),
            BuildError::InUse => write!(f, "{}", UpdateError::InUse),
            BuildError::Io(m) => write!(f, "could not write the CVE database: {m}"),
            BuildError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<UpdateError> for BuildError {
    fn from(e: UpdateError) -> Self {
        match e {
            UpdateError::InUse => BuildError::InUse,
            e => BuildError::Io(e.to_string()),
        }
    }
}

impl From<DbError> for BuildError {
    fn from(e: DbError) -> Self {
        BuildError::Db(e)
    }
}

/// A finished build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub info: DbInfo,
    /// Refreshed the existing file rather than building a new one.
    pub refreshed: bool,
    /// CVE records read from NVD (for a refresh: the changed ones).
    pub read: u64,
}

/// What [`build`] would do with `dest` now. Opens it read-only briefly.
pub fn plan(dest: &Path) -> Plan {
    plan_at(dest, &products(), time::now())
}

fn plan_at(dest: &Path, products: &convert::Products, now: u64) -> Plan {
    let full = |why: &str| Plan::Full(why.to_string());
    let db = match Database::open(dest) {
        Ok(db) => db,
        Err(DbError::NotFound) => return full("no CVE data yet"),
        Err(DbError::OldSchema(_)) => return full("the current data is in an older format"),
        Err(_) => return full("the current file is unusable"),
    };
    let Some(watermark) = db.meta("nvd_last_modified").and_then(|s| time::parse(&s)) else {
        return full("the current data has no NVD sync time");
    };
    if db.meta("nvd_products") != Some(fingerprint(products)) {
        return full("the current data was built for a different rmap version");
    }
    let age = now.saturating_sub(watermark);
    if age > MAX_REFRESH_AGE {
        return full("the last NVD sync is more than 118 days old");
    }
    Plan::Refresh {
        watermark,
        age_days: age / DAY,
    }
}

/// Builds or refreshes `opts.dest`. `progress` is called from this thread;
/// setting `cancel` stops before the next request (or retry wait) and
/// leaves `dest` as it was.
pub fn build(
    opts: &BuildOptions,
    progress: &mut dyn FnMut(BuildProgress),
    cancel: &AtomicBool,
) -> Result<Built, BuildError> {
    for url in [&opts.nvd_url, &opts.kev_url] {
        rmap_vuln::check_url(url).map_err(|e| BuildError::Network(e.to_string()))?;
    }
    let products = products();
    let now = time::now();
    let mut plan = if opts.allow_refresh {
        plan_at(&opts.dest, &products, now)
    } else {
        Plan::Full("requested".into())
    };
    let part = PartFile::new(&opts.dest)?;
    // A refresh edits a copy of the current file. A copy that can't be
    // opened for that (an unexpected trigger, say) means a full build.
    let mut writer = None;
    if let Plan::Refresh { .. } = plan {
        let opened = std::fs::copy(&opts.dest, part.path())
            .map_err(|e| BuildError::Io(e.to_string()))
            .and_then(|_| Writer::open_existing(part.path()).map_err(BuildError::Db));
        match opened {
            Ok(w) => writer = Some(w),
            Err(e) => {
                rmap_log::info!(
                    "NVD build: can't refresh the current file ({e}); building in full"
                );
                plan = Plan::Full("the current file can't be refreshed".into());
                let _ = std::fs::remove_file(part.path());
            }
        }
    }
    let window = match plan {
        Plan::Refresh { watermark, .. } => Some((
            time::nvd_param(watermark.min(now).saturating_sub(OVERLAP)),
            time::nvd_param(now),
        )),
        Plan::Full(_) => None,
    };
    rmap_log::info!(
        "NVD build: {plan:?}; API key {}; into {}",
        if opts.api_key.is_some() {
            "set"
        } else {
            "not set (slow rate limit)"
        },
        opts.dest.display()
    );

    let mut client = Client::new(opts, cancel);
    progress(BuildProgress::Kev);
    let kev = convert::kev_dates(&client.get_json(&opts.kev_url, KEV_BODY_LIMIT, progress)?);
    rmap_log::info!("CISA KEV: {} CVEs", kev.len());
    if kev.len() < MIN_KEV {
        return Err(BuildError::BadData(format!(
            "only {} KEV entries; expected at least {MIN_KEV}",
            kev.len()
        )));
    }
    let fetched = fetch_nvd(
        &mut client,
        opts,
        window.as_ref(),
        &products,
        &kev,
        progress,
    )?;
    check(cancel)?;

    progress(BuildProgress::Writing);
    let refreshed = writer.is_some();
    let mut w = match writer {
        Some(w) => w,
        None => Writer::create(part.path())?,
    };
    if refreshed {
        // Changed CVEs are deleted and re-added; rejected ones, or ones
        // that no longer affect a product rmap detects, stay deleted.
        for id in &fetched.ids {
            w.remove(id)?;
        }
    }
    for e in fetched.entries.values() {
        w.add(e)?;
    }
    if refreshed {
        w.replace_kev(kev.iter().map(|(id, date)| (id.as_str(), date.as_str())))?;
    }
    w.set_meta("built_at", &time::rfc3339(now))?;
    w.set_meta("source", &opts.source)?;
    w.set_meta("nvd_products", &fingerprint(&products))?;
    // Never move the watermark back: a refresh re-reads the overlap.
    let old = match plan {
        Plan::Refresh { watermark, .. } => watermark,
        Plan::Full(_) => 0,
    };
    if let Some(lm) = fetched
        .last_modified
        .filter(|lm| time::parse(lm).is_some_and(|t| t > old))
    {
        w.set_meta("nvd_last_modified", &lm)?;
    }
    w.finish()?;

    progress(BuildProgress::Verifying);
    // Opened and closed again before the rename: Windows can't rename an
    // open file.
    let info = Database::open(part.path())?.info().clone();
    if !refreshed && info.cve_count != fetched.entries.len() as u64 {
        return Err(BuildError::Db(DbError::Invalid(format!(
            "it has {} CVEs, {} were written",
            info.cve_count,
            fetched.entries.len()
        ))));
    }
    if info.cve_count < MIN_CVES && opts.max_pages.is_none() {
        return Err(BuildError::TooFew(info.cve_count));
    }
    check(cancel)?;
    part.install(&opts.dest)?;
    rmap_log::info!(
        "NVD build done: {} {} CVEs ({} read from NVD) at {}",
        if refreshed { "refreshed," } else { "built," },
        info.cve_count,
        fetched.read,
        opts.dest.display()
    );
    Ok(Built {
        info,
        refreshed,
        read: fetched.read,
    })
}

fn check(cancel: &AtomicBool) -> Result<(), BuildError> {
    if cancel.load(Ordering::Relaxed) {
        Err(BuildError::Cancelled)
    } else {
        Ok(())
    }
}

/// NVD (vendor, product) pairs rmap can detect.
fn products() -> convert::Products {
    rmap_detect::cpe::nvd_products()
        .map(|(v, p)| (v.to_string(), p.to_string()))
        .collect()
}

/// Identifies the product table and conversion a file was built with
/// (FNV-1a over the sorted pairs), so a refresh never mixes in rows from a
/// different rmap version - one that detects more products would be
/// missing those products' older CVEs.
fn fingerprint(products: &convert::Products) -> String {
    let mut pairs: Vec<_> = products.iter().collect();
    pairs.sort();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (v, p) in pairs {
        for b in v.bytes().chain(*b":").chain(p.bytes()).chain(*b"\n") {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("v{CONVERT_VERSION}-{h:016x}")
}

struct Fetched {
    entries: BTreeMap<String, Entry>,
    /// Every CVE id read (refresh only).
    ids: BTreeSet<String>,
    last_modified: Option<String>,
    read: u64,
}

/// Every NVD page (modified within `window`, if given), converted and
/// filtered, keyed by CVE id (a CVE that moves between pages mid-sync is
/// kept once), plus the newest `lastModified` seen.
fn fetch_nvd(
    client: &mut Client,
    opts: &BuildOptions,
    window: Option<&(String, String)>,
    products: &convert::Products,
    kev: &HashMap<String, String>,
    progress: &mut dyn FnMut(BuildProgress),
) -> Result<Fetched, BuildError> {
    let mut out = Fetched {
        entries: BTreeMap::new(),
        ids: BTreeSet::new(),
        last_modified: None,
        read: 0,
    };
    let started = Instant::now();
    let mut page_no = 0u64;
    loop {
        let mut url = format!(
            "{}?startIndex={}&resultsPerPage={PAGE_SIZE}",
            opts.nvd_url, out.read
        );
        if let Some((from, to)) = window {
            url += &format!("&lastModStartDate={from}&lastModEndDate={to}");
        }
        let json = client.get_json(&url, NVD_BODY_LIMIT, progress)?;
        let page = convert::convert_page(&json, products, kev).ok_or_else(|| {
            BuildError::BadData(format!("startIndex={}: not an NVD CVE page", out.read))
        })?;
        page_no += 1;
        out.read += page.returned as u64;
        if page.last_modified > out.last_modified {
            out.last_modified = page.last_modified;
        }
        if window.is_some() {
            out.ids.extend(page.ids);
        }
        for e in page.entries {
            out.entries.insert(e.finding.id.clone(), e);
        }
        let total = page.total_results;
        let left = total.saturating_sub(out.read);
        let eta = (out.read > 0 && left > 0)
            .then(|| started.elapsed().mul_f64(left as f64 / out.read as f64));
        rmap_log::debug!(
            "NVD page {page_no}: {}/{total} CVEs read, {} kept",
            out.read,
            out.entries.len()
        );
        progress(BuildProgress::Nvd {
            read: out.read.min(total),
            total,
            eta,
        });
        if out.read >= total || opts.max_pages.is_some_and(|m| page_no >= m) {
            return Ok(out);
        }
        if page.returned == 0 {
            return Err(BuildError::BadData(format!(
                "NVD returned an empty page at startIndex={}",
                out.read
            )));
        }
    }
}

/// HTTP with NVD's rate limit, retries and cancelling.
struct Client<'a> {
    agent: ureq::Agent,
    key: Option<&'a str>,
    spacing: Duration,
    backoff: Duration,
    last: Option<Instant>,
    cancel: &'a AtomicBool,
}

impl<'a> Client<'a> {
    fn new(opts: &'a BuildOptions, cancel: &'a AtomicBool) -> Client<'a> {
        let agent = ureq::Agent::config_builder()
            // A redirect could carry the apiKey header to another host.
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_global(Some(Duration::from_secs(300)))
            .user_agent(concat!("rmap/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Client {
            agent,
            key: opts.api_key.as_deref(),
            spacing: opts.spacing,
            backoff: opts.backoff,
            last: None,
            cancel,
        }
    }

    /// Sleeps `d` in short steps, stopping early when cancelled.
    fn sleep(&self, d: Duration) -> Result<(), BuildError> {
        let until = Instant::now() + d;
        loop {
            check(self.cancel)?;
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(());
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }

    /// GETs and parses JSON, retrying rate limiting (403/429), server
    /// errors, network errors and unparseable bodies with backoff.
    fn get_json(
        &mut self,
        url: &str,
        limit: u64,
        progress: &mut dyn FnMut(BuildProgress),
    ) -> Result<Value, BuildError> {
        let mut attempt = 0;
        loop {
            if let Some(last) = self.last {
                self.sleep(self.spacing.saturating_sub(last.elapsed()))?;
            }
            check(self.cancel)?;
            self.last = Some(Instant::now());
            attempt += 1;
            let err = match self.get_once(url, limit) {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let retry = match &err {
                ureq::Error::StatusCode(code) => matches!(code, 403 | 429 | 500..=599),
                _ => true,
            };
            if !retry || attempt >= ATTEMPTS {
                let hint = match &err {
                    ureq::Error::StatusCode(404) if self.key.is_some() => {
                        "; NVD answers 404 to an API key it doesn't accept, so check the key"
                    }
                    _ => "",
                };
                return Err(BuildError::Network(format!(
                    "GET {url}: {err} (attempt {attempt}){hint}"
                )));
            }
            let wait = self.backoff * (1 << attempt);
            rmap_log::info!("GET {url}: {err}; retrying in {}s", wait.as_secs());
            progress(BuildProgress::Retrying { wait });
            self.sleep(wait)?;
        }
    }

    fn get_once(&self, url: &str, limit: u64) -> Result<Value, ureq::Error> {
        let loopback = rmap_vuln::check_url(url).map_err(|e| ureq::Error::BadUri(e.to_string()))?;
        let mut req = self.agent.get(url);
        if let Some(k) = self.key {
            req = req.header("apiKey", k);
        }
        if loopback {
            // A proxy from the environment never helps reach this computer.
            req = req.config().proxy(None).build();
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

#[cfg(test)]
mod tests;
