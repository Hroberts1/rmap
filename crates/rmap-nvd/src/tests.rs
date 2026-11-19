//! End-to-end builds against a loopback HTTP server: no network, no root.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;

/// A unique directory under the temp dir, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rmap-nvd-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn db(&self) -> PathBuf {
        self.0.join("vulns.db")
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Requests a [`serve`] server saw: target and `apiKey` header.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A tiny HTTP/1.1 server on 127.0.0.1, one connection per request,
/// answering each request target with `handler`. Returns its base URL.
fn serve(handler: impl Fn(&str) -> (u16, String) + Send + 'static) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 16 * 1024 {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let req = String::from_utf8_lossy(&req);
            let target = req.split(' ').nth(1).unwrap_or("").to_string();
            let key = req.lines().find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("apikey")
                    .then(|| value.trim().to_string())
            });
            log.lock().unwrap().push((target.clone(), key));
            let (status, body) = handler(&target);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });
    (base, seen)
}

fn opts(dest: PathBuf, base: &str) -> BuildOptions {
    let mut o = BuildOptions::new(dest, Some("0f1e2d3c-test-key".into()));
    o.nvd_url = format!("{base}/nvd");
    o.kev_url = format!("{base}/kev");
    o.spacing = Duration::ZERO;
    o.backoff = Duration::ZERO;
    o
}

/// `count` KEV entries, plus `extra` ids added on 2024-07-10.
fn kev(count: usize, extra: &[&str]) -> String {
    let mut list: Vec<Value> = (0..count)
        .map(|i| json!({"cveID": format!("CVE-1999-{i:05}"), "dateAdded": "2022-01-01"}))
        .collect();
    list.extend(
        extra
            .iter()
            .map(|id| json!({"cveID": id, "dateAdded": "2024-07-10"})),
    );
    json!({ "vulnerabilities": list }).to_string()
}

/// An OpenSSH CVE affecting exactly `version`.
fn cve(id: &str, version: &str, modified: &str) -> Value {
    json!({"cve": {
        "id": id,
        "vulnStatus": "Analyzed",
        "published": "2024-07-01T13:15:06.467",
        "lastModified": modified,
        "descriptions": [{"lang": "en", "value": format!("{id} in sshd")}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": true, "criteria": format!("cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*")}
        ]}]}]
    }})
}

fn page(total: usize, cves: Vec<Value>) -> String {
    json!({"totalResults": total, "vulnerabilities": cves}).to_string()
}

/// NVD's `lastModified` form, `days` ago.
fn modified(days: u64) -> String {
    let s = time::rfc3339(time::now() - days * DAY);
    format!("{}.000", &s[..19])
}

fn ssh(version: &str) -> String {
    format!("cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*")
}

/// The NVD half of a full sync: 601 CVEs over two pages, CVE-2000-00000
/// to -00600, CVE-2000-00000 on version 1.0 and modified `days` ago.
fn full_nvd(target: &str, days: u64) -> (u16, String) {
    let mut all: Vec<Value> = (0..601)
        .map(|i| cve(&format!("CVE-2000-{i:05}"), "1.0", &modified(days + 1)))
        .collect();
    all[0] = cve("CVE-2000-00000", "1.0", &modified(days));
    if target.contains("startIndex=0&") {
        (200, page(601, all[..600].to_vec()))
    } else if target.contains("startIndex=600&") {
        (200, page(601, all[600..].to_vec()))
    } else {
        (400, "bad startIndex".into())
    }
}

fn build_ok(o: &BuildOptions) -> (Built, Vec<BuildProgress>) {
    let mut seen = Vec::new();
    let built = build(o, &mut |p| seen.push(p), &AtomicBool::new(false)).unwrap();
    (built, seen)
}

#[test]
fn full_build_then_incremental_refresh() {
    let dir = TempDir::new("full");
    let (base, seen) = serve(|t| {
        if t.starts_with("/kev") {
            (200, kev(600, &["CVE-2000-00001"]))
        } else {
            full_nvd(t, 3)
        }
    });
    let o = opts(dir.db(), &base);
    let (built, progress) = build_ok(&o);
    assert!(!built.refreshed);
    assert_eq!((built.read, built.info.cve_count), (601, 601));
    assert_eq!(built.info.source, LOCAL_SOURCE);
    assert_eq!(dir.files(), ["vulns.db"], "no .part or journal left");
    // File format bytes 18/19: 1 = rollback journal, so it opens read-only.
    let header = fs::read(dir.db()).unwrap();
    assert_eq!((header[18], header[19]), (1, 1));
    assert_eq!(progress.first(), Some(&BuildProgress::Kev));
    assert!(progress.contains(&BuildProgress::Nvd {
        read: 601,
        total: 601,
        eta: None
    }));
    assert!(matches!(
        progress[progress.len() - 2..],
        [BuildProgress::Writing, BuildProgress::Verifying]
    ));
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    for (target, key) in &requests {
        assert_eq!(key.as_deref(), Some("0f1e2d3c-test-key"), "{target}");
        assert!(!target.contains("test-key"), "key never in a URL: {target}");
        assert!(!target.contains("lastMod"), "full sync: {target}");
    }
    let db = Database::open(&dir.db()).unwrap();
    assert_eq!(db.meta("nvd_last_modified"), Some(modified(3)));
    assert_eq!(db.meta("nvd_products"), Some(fingerprint(&products())));
    let found = db.find(&ssh("1.0"));
    assert_eq!(found.len(), 601);
    let kev_of = |db: &Database, id: &str| {
        db.find(&ssh("1.0"))
            .into_iter()
            .chain(db.find(&ssh("2.0")))
            .find(|f| f.id == id)
            .map(|f| f.kev_added)
    };
    assert_eq!(
        kev_of(&db, "CVE-2000-00001"),
        Some(Some("2024-07-10".into()))
    );
    drop(db);

    let watermark = time::parse(&modified(3)).unwrap();
    assert_eq!(
        plan(&dir.db()),
        Plan::Refresh {
            watermark,
            age_days: 3
        }
    );

    // NVD now says: 00000 moved to version 2.0, 00002 was rejected, and
    // 09999 is new and exploited; 00001 left the KEV list.
    let (base, seen) = serve(|t| {
        if t.starts_with("/kev") {
            (200, kev(600, &["CVE-2000-09999"]))
        } else if t.contains("startIndex=0&") && t.contains("lastModStartDate=") {
            let mut rejected = cve("CVE-2000-00002", "1.0", &modified(1));
            rejected["cve"]["vulnStatus"] = "Rejected".into();
            (
                200,
                page(
                    3,
                    vec![
                        cve("CVE-2000-00000", "2.0", &modified(2)),
                        rejected,
                        cve("CVE-2000-09999", "1.0", &modified(1)),
                    ],
                ),
            )
        } else {
            (400, "unexpected".into())
        }
    });
    let o = opts(dir.db(), &base);
    let (built, _) = build_ok(&o);
    assert!(built.refreshed);
    assert_eq!((built.read, built.info.cve_count), (3, 601));
    assert_eq!(dir.files(), ["vulns.db"]);
    let requests = seen.lock().unwrap().clone();
    let nvd = &requests[1].0;
    let from = time::nvd_param(watermark - DAY);
    assert!(
        nvd.contains(&format!("&lastModStartDate={from}&lastModEndDate=")),
        "{nvd}"
    );
    let db = Database::open(&dir.db()).unwrap();
    let on = |v: &str| -> Vec<String> { db.find(&ssh(v)).into_iter().map(|f| f.id).collect() };
    assert_eq!(on("2.0"), ["CVE-2000-00000"]);
    assert!(!on("1.0").contains(&"CVE-2000-00000".to_string()));
    assert!(
        !on("1.0").contains(&"CVE-2000-00002".to_string()),
        "rejected"
    );
    assert!(on("1.0").contains(&"CVE-2000-09999".to_string()));
    assert_eq!(kev_of(&db, "CVE-2000-00001"), Some(None), "left KEV");
    assert_eq!(
        kev_of(&db, "CVE-2000-09999"),
        Some(Some("2024-07-10".into()))
    );
    assert_eq!(db.meta("nvd_last_modified"), Some(modified(1)));
    assert_eq!(db.info().source, LOCAL_SOURCE);
}

#[test]
fn refresh_with_no_changes_keeps_the_watermark() {
    let dir = TempDir::new("nochange");
    let (base, _) = serve(|t| {
        if t.starts_with("/kev") {
            (200, kev(600, &[]))
        } else {
            full_nvd(t, 5)
        }
    });
    build_ok(&opts(dir.db(), &base));
    let (base, _) = serve(|t| {
        if t.starts_with("/kev") {
            (200, kev(600, &[]))
        } else {
            (200, page(0, vec![]))
        }
    });
    let (built, _) = build_ok(&opts(dir.db(), &base));
    assert!(built.refreshed);
    assert_eq!((built.read, built.info.cve_count), (0, 601));
    let db = Database::open(&dir.db()).unwrap();
    assert_eq!(db.meta("nvd_last_modified"), Some(modified(5)));
}

#[test]
fn plan_falls_back_to_a_full_build() {
    let dir = TempDir::new("plan");
    let p = products();
    let now = time::parse("2026-11-19T00:00:00Z").unwrap();
    assert_eq!(
        plan_at(&dir.db(), &p, now),
        Plan::Full("no CVE data yet".into())
    );
    fs::write(dir.db(), b"not sqlite").unwrap();
    assert!(matches!(plan_at(&dir.db(), &p, now), Plan::Full(w) if w.contains("unusable")));
    fs::remove_file(dir.db()).unwrap();

    let write = |meta: &[(&str, &str)]| {
        let _ = fs::remove_file(dir.db());
        let mut w = Writer::create(&dir.db()).unwrap();
        for (k, v) in meta {
            w.set_meta(k, v).unwrap();
        }
        w.finish().unwrap();
    };
    let fp = fingerprint(&p);
    write(&[("nvd_products", &fp)]);
    assert!(matches!(plan_at(&dir.db(), &p, now), Plan::Full(w) if w.contains("sync time")));
    write(&[
        ("nvd_last_modified", "2026-11-01T00:00:00.000\u{1b}"),
        ("nvd_products", &fp),
    ]);
    assert!(matches!(plan_at(&dir.db(), &p, now), Plan::Full(w) if w.contains("sync time")));
    write(&[("nvd_last_modified", "2026-11-01T00:00:00.000")]);
    assert!(matches!(plan_at(&dir.db(), &p, now), Plan::Full(w) if w.contains("rmap version")));
    write(&[
        ("nvd_last_modified", "2026-07-23T23:59:59.000"),
        ("nvd_products", &fp),
    ]);
    assert!(matches!(plan_at(&dir.db(), &p, now), Plan::Full(w) if w.contains("118 days")));
    write(&[
        ("nvd_last_modified", "2026-07-24T00:00:00.000"),
        ("nvd_products", &fp),
    ]);
    assert_eq!(
        plan_at(&dir.db(), &p, now),
        Plan::Refresh {
            watermark: time::parse("2026-07-24T00:00:00").unwrap(),
            age_days: 118
        }
    );
    // A watermark in the future (a clock that was ahead) still refreshes.
    write(&[
        ("nvd_last_modified", "2026-12-01T00:00:00.000"),
        ("nvd_products", &fp),
    ]);
    assert!(matches!(
        plan_at(&dir.db(), &p, now),
        Plan::Refresh { age_days: 0, .. }
    ));

    let mut fewer = p.clone();
    let first = fewer.iter().next().unwrap().clone();
    fewer.remove(&first);
    assert_ne!(fingerprint(&fewer), fp);
    assert_eq!(fingerprint(&p.clone()), fp, "stable");
}

#[test]
fn a_file_with_a_trigger_is_rebuilt_in_full() {
    let dir = TempDir::new("trigger");
    let handler = |t: &str| {
        if t.starts_with("/kev") {
            (200, kev(600, &[]))
        } else {
            full_nvd(t, 2)
        }
    };
    let (base, _) = serve(handler);
    build_ok(&opts(dir.db(), &base));
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch("CREATE TRIGGER t AFTER DELETE ON cve BEGIN DELETE FROM meta; END;")
        .unwrap();
    drop(conn);
    assert!(matches!(plan(&dir.db()), Plan::Refresh { .. }));
    let (base, seen) = serve(handler);
    let (built, _) = build_ok(&opts(dir.db(), &base));
    assert!(!built.refreshed);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|(t, _)| !t.contains("lastMod"))
    );
    assert_eq!(dir.files(), ["vulns.db"]);
}

/// Runs a build that must fail, over an existing database, and checks the
/// database was left exactly as it was with nothing beside it.
fn build_fails(
    handler: impl Fn(&str) -> (u16, String) + Send + 'static,
    cancel_at: Option<u64>,
) -> (BuildError, usize, Vec<BuildProgress>) {
    let dir = TempDir::new("fail");
    fs::write(dir.db(), b"the old database").unwrap();
    let (base, seen) = serve(handler);
    let o = opts(dir.db(), &base);
    let cancel = AtomicBool::new(false);
    let mut progress = Vec::new();
    let err = build(
        &o,
        &mut |p| {
            if let BuildProgress::Nvd { read, .. } = p
                && Some(read) == cancel_at
            {
                cancel.store(true, Ordering::Relaxed);
            }
            progress.push(p);
        },
        &cancel,
    )
    .unwrap_err();
    assert_eq!(fs::read(dir.db()).unwrap(), b"the old database", "{err}");
    assert_eq!(dir.files(), ["vulns.db"], "{err}");
    let n = seen.lock().unwrap().len();
    (err, n, progress)
}

#[test]
fn failures_and_cancel_leave_the_old_database() {
    // Too few CVEs for a full database.
    let (err, _, _) = build_fails(
        |t| {
            if t.starts_with("/kev") {
                (200, kev(600, &[]))
            } else {
                (200, page(1, vec![cve("CVE-2000-1", "1.0", &modified(1))]))
            }
        },
        None,
    );
    assert_eq!(err, BuildError::TooFew(1));

    // Cancelled after the first NVD page.
    let (err, requests, _) = build_fails(
        |t| {
            if t.starts_with("/kev") {
                (200, kev(600, &[]))
            } else {
                full_nvd(t, 1)
            }
        },
        Some(600),
    );
    assert_eq!(err, BuildError::Cancelled);
    assert_eq!(requests, 2, "stops before the next request");

    // A rejected key: NVD's 404 is not retried, and the hint says why.
    let (err, requests, _) = build_fails(|_| (404, "Invalid apiKey".into()), None);
    assert!(
        matches!(&err, BuildError::Network(m) if m.contains("404") && m.contains("check the key")),
        "{err}"
    );
    assert!(!err.to_string().contains("test-key"));
    assert_eq!(requests, 1);

    // Rate limiting is retried with backoff, then given up on.
    let (err, requests, progress) = build_fails(|_| (429, "slow down".into()), None);
    assert!(
        matches!(&err, BuildError::Network(m) if m.contains("429")),
        "{err}"
    );
    assert_eq!(requests, ATTEMPTS as usize);
    assert_eq!(
        progress
            .iter()
            .filter(|p| matches!(p, BuildProgress::Retrying { .. }))
            .count(),
        ATTEMPTS as usize - 1
    );

    // Not KEV, not NVD.
    let (err, _, _) = build_fails(|_| (200, "{\"vulnerabilities\": []}".into()), None);
    assert!(matches!(err, BuildError::BadData(m) if m.contains("KEV")));
    let (err, _, _) = build_fails(
        |t| {
            if t.starts_with("/kev") {
                (200, kev(600, &[]))
            } else {
                (200, "{\"message\": \"hello\"}".into())
            }
        },
        None,
    );
    assert!(matches!(err, BuildError::BadData(m) if m.contains("not an NVD CVE page")));
}

#[test]
fn a_server_error_is_retried_then_succeeds() {
    let dir = TempDir::new("retry");
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let (base, _) = serve(move |t| {
        if t.starts_with("/kev") && c.fetch_add(1, Ordering::Relaxed) == 0 {
            (503, "busy".into())
        } else if t.starts_with("/kev") {
            (200, kev(600, &[]))
        } else {
            full_nvd(t, 1)
        }
    });
    let (built, progress) = build_ok(&opts(dir.db(), &base));
    assert_eq!(built.info.cve_count, 601);
    assert!(progress.contains(&BuildProgress::Retrying {
        wait: Duration::ZERO
    }));
}

#[test]
fn only_https_or_loopback_urls_are_used() {
    let dir = TempDir::new("insecure");
    let mut o = opts(dir.db(), "http://127.0.0.1:9");
    o.nvd_url = "http://services.nvd.nist.gov/rest/json/cves/2.0".into();
    let err = build(&o, &mut |_| {}, &AtomicBool::new(false)).unwrap_err();
    assert!(
        matches!(&err, BuildError::Network(m) if m.contains("https")),
        "{err}"
    );
    assert!(dir.files().is_empty());
    let o = BuildOptions::new(dir.db(), None);
    assert_eq!(o.spacing, Duration::from_secs(6), "keyless rate limit");
    assert!(o.nvd_url.starts_with("https://") && o.kev_url.starts_with("https://"));
}
