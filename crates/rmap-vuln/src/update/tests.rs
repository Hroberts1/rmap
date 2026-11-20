use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::{Entry, VulnSeverity, Vulnerability, Writer};
use rmap_core::sha256::hex;

/// A unique directory under the temp dir, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rmap-vuln-update-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
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

/// The bytes of a real database with `cves` CVEs.
fn db_bytes(cves: usize) -> Vec<u8> {
    let dir = TempDir::new("fixture");
    let path = dir.0.join("fixture.db");
    let mut w = Writer::create(&path).unwrap();
    for i in 0..cves {
        w.add(&Entry {
            finding: Vulnerability {
                id: format!("CVE-2026-{i:04}"),
                summary: "test".into(),
                severity: VulnSeverity::High,
                score: Some(7.5),
                published: Some("2026-01-01".into()),
                kev_added: None,
            },
            matches: Vec::new(),
        })
        .unwrap();
    }
    w.set_meta("built_at", "2026-11-01T06:12:00Z").unwrap();
    w.set_meta("source", "test").unwrap();
    w.finish().unwrap();
    fs::read(&path).unwrap()
}

fn digest(bytes: &[u8]) -> String {
    let mut s = Sha256::new();
    s.update(bytes);
    hex(&s.finish())
}

fn manifest_json(size: usize, sha256: &str, cve_count: u64, db: &str) -> String {
    format!(
        r#"{{"schema_version":1,"built_at":"2026-11-01T06:12:00Z","cve_count":{cve_count},"source":"test","size":{size},"sha256":"{sha256}","db":"{db}"}}"#
    )
}

/// The manifest for serving `db` at `vulns.db` next to it.
fn manifest_for(db: &[u8], cve_count: u64) -> String {
    manifest_json(db.len(), &digest(db), cve_count, "vulns.db")
}

struct Reply {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

fn ok(body: impl Into<Vec<u8>>) -> Reply {
    Reply {
        status: 200,
        location: None,
        body: body.into(),
    }
}

fn redirect(to: &str) -> Reply {
    Reply {
        status: 302,
        location: Some(to.into()),
        body: Vec::new(),
    }
}

fn status(code: u16) -> Reply {
    Reply {
        status: code,
        location: None,
        body: b"error".to_vec(),
    }
}

/// A tiny HTTP/1.1 server on 127.0.0.1 answering GETs from `routes`
/// (404 otherwise), one connection per request. Returns its base URL.
/// The thread is left blocked in `accept` when the test ends.
fn serve(routes: Vec<(&str, Reply)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let routes: HashMap<String, Reply> = routes
        .into_iter()
        .map(|(p, r)| (p.to_string(), r))
        .collect();
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
            let path = req.split(' ').nth(1).unwrap_or("");
            let not_found = status(404);
            let reply = routes.get(path).unwrap_or(&not_found);
            let mut head = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                reply.status,
                reply.body.len()
            );
            if let Some(to) = &reply.location {
                head.push_str(&format!("Location: {to}\r\n"));
            }
            head.push_str("\r\n");
            // The client may hang up early (e.g. a too-long body).
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&reply.body);
        }
    });
    base
}

/// `dir/vulns.db` holding a 1-CVE database; returns its path and bytes.
fn existing_db(dir: &TempDir) -> (PathBuf, Vec<u8>) {
    let dest = dir.0.join("vulns.db");
    let bytes = db_bytes(1);
    fs::write(&dest, &bytes).unwrap();
    (dest, bytes)
}

/// Runs an update against `base` into a directory that already holds a
/// database, and checks that the failure left it alone with no `.part`.
fn update_fails(base: &str) -> UpdateError {
    let dir = TempDir::new("fail");
    let (dest, before) = existing_db(&dir);
    let err = update(&format!("{base}/vulns.json"), &dest, &mut |_| {}).unwrap_err();
    assert_eq!(fs::read(&dest).unwrap(), before, "dest changed after {err}");
    assert_eq!(dir.files(), ["vulns.db"], "leftover files after {err}");
    err
}

#[test]
fn update_installs_into_a_new_directory() {
    let db = db_bytes(3);
    let base = serve(vec![
        ("/vulns.json", ok(manifest_for(&db, 3))),
        ("/vulns.db", ok(db.clone())),
    ]);
    let dir = TempDir::new("new");
    let dest = dir.0.join("sub").join("vulns.db");
    let mut seen = Vec::new();
    let info = update(&format!("{base}/vulns.json"), &dest, &mut |p| seen.push(p)).unwrap();
    assert_eq!(info.cve_count, 3);
    assert_eq!(info.built_at, "2026-11-01T06:12:00Z");
    assert_eq!(fs::read(&dest).unwrap(), db);
    let total = db.len() as u64;
    assert_eq!(seen.first(), Some(&Progress::Manifest));
    assert!(seen.contains(&Progress::Downloading { done: total, total }));
    assert_eq!(
        &seen[seen.len() - 2..],
        [Progress::Verifying, Progress::Installing]
    );
}

#[test]
fn update_replaces_an_older_database() {
    let db = db_bytes(5);
    let base = serve(vec![
        ("/vulns.json", ok(manifest_for(&db, 5))),
        ("/vulns.db", ok(db)),
    ]);
    let dir = TempDir::new("replace");
    let (dest, _) = existing_db(&dir);
    update(&format!("{base}/vulns.json"), &dest, &mut |_| {}).unwrap();
    assert_eq!(Database::open(&dest).unwrap().info().cve_count, 5);
    assert_eq!(dir.files(), ["vulns.db"]);
}

#[test]
fn wrong_hash_is_rejected() {
    let db = db_bytes(2);
    let manifest = manifest_json(db.len(), &"ab".repeat(32), 2, "vulns.db");
    let base = serve(vec![("/vulns.json", ok(manifest)), ("/vulns.db", ok(db))]);
    assert_eq!(update_fails(&base), UpdateError::HashMismatch);
}

#[test]
fn short_and_long_bodies_are_rejected() {
    let db = db_bytes(2);
    let manifest = manifest_for(&db, 2);
    let short = db[..db.len() - 1].to_vec();
    let mut long = db.clone();
    long.extend_from_slice(&[0; 100_000]);
    for body in [short, long] {
        let base = serve(vec![
            ("/vulns.json", ok(manifest.clone())),
            ("/vulns.db", ok(body)),
        ]);
        assert_eq!(update_fails(&base), UpdateError::SizeMismatch);
    }
}

#[test]
fn garbage_with_a_matching_hash_is_rejected() {
    let garbage = vec![0x5a; 4096];
    let manifest = manifest_json(garbage.len(), &digest(&garbage), 0, "vulns.db");
    let base = serve(vec![
        ("/vulns.json", ok(manifest)),
        ("/vulns.db", ok(garbage)),
    ]);
    assert!(matches!(update_fails(&base), UpdateError::InvalidDb(_)));
}

#[test]
fn cve_count_must_agree_with_the_manifest() {
    let db = db_bytes(2);
    let base = serve(vec![
        ("/vulns.json", ok(manifest_for(&db, 99))),
        ("/vulns.db", ok(db)),
    ]);
    assert!(matches!(update_fails(&base), UpdateError::InvalidDb(_)));
}

#[test]
fn http_errors_are_reported() {
    let base = serve(vec![("/vulns.json", status(500))]);
    assert_eq!(update_fails(&base), UpdateError::Http(500));
    // Manifest fine, database missing.
    let db = db_bytes(1);
    let base = serve(vec![("/vulns.json", ok(manifest_for(&db, 1)))]);
    assert_eq!(update_fails(&base), UpdateError::Http(404));
}

#[test]
fn too_new_manifest_asks_for_a_newer_rmap() {
    let base = serve(vec![(
        "/vulns.json",
        ok(r#"{"schema_version":2,"something":"else"}"#),
    )]);
    let err = update_fails(&base);
    assert_eq!(err, UpdateError::TooNewSchema(2));
    assert!(err.to_string().contains("update rmap"));
}

#[test]
fn oversized_manifest_is_rejected() {
    let base = serve(vec![("/vulns.json", ok(vec![b' '; 70_000]))]);
    assert!(matches!(update_fails(&base), UpdateError::BadManifest(_)));
}

#[test]
fn redirects_are_followed_and_checked() {
    let db = db_bytes(1);
    let base = serve(vec![
        ("/old.json", redirect("/vulns.json")),
        (
            "/vulns.json",
            ok(manifest_json(db.len(), &digest(&db), 1, "/r/db")),
        ),
        ("/r/db", redirect("db2")),
        ("/r/db2", ok(db)),
        ("/loop", redirect("/loop")),
        ("/downgrade", redirect("http://192.0.2.1/vulns.json")),
    ]);
    let dir = TempDir::new("redirect");
    let dest = dir.0.join("vulns.db");
    update(&format!("{base}/old.json"), &dest, &mut |_| {}).unwrap();
    assert_eq!(dir.files(), ["vulns.db"]);

    assert!(matches!(
        fetch_manifest(&format!("{base}/loop")),
        Err(UpdateError::Network(_))
    ));
    assert!(matches!(
        fetch_manifest(&format!("{base}/downgrade")),
        Err(UpdateError::Insecure(_))
    ));
}

#[test]
fn manifest_pointing_at_plain_http_is_rejected() {
    let base = serve(vec![(
        "/vulns.json",
        ok(manifest_json(
            10,
            &"00".repeat(32),
            1,
            "http://192.0.2.1/vulns.db",
        )),
    )]);
    assert!(matches!(update_fails(&base), UpdateError::Insecure(_)));
}

#[test]
fn insecure_urls_are_refused_without_connecting() {
    let dir = TempDir::new("insecure");
    let (dest, _) = existing_db(&dir);
    for url in [
        "http://192.0.2.1/vulns.json",
        "ftp://192.0.2.1/vulns.json",
        "file:///etc/passwd",
        "https://user:pw@192.0.2.1/vulns.json",
    ] {
        let start = std::time::Instant::now();
        assert!(
            matches!(
                update(url, &dest, &mut |_| {}),
                Err(UpdateError::Insecure(_))
            ),
            "{url}"
        );
        assert!(start.elapsed() < Duration::from_secs(2), "{url}");
    }
    assert_eq!(dir.files(), ["vulns.db"]);
}

#[test]
fn install_refuses_oversized_manifest() {
    let manifest = Manifest {
        schema_version: 1,
        built_at: "x".into(),
        cve_count: 0,
        source: String::new(),
        size: MAX_DB_BYTES + 1,
        sha256: [0; 32],
        db_url: "http://192.0.2.1/vulns.db".into(),
    };
    let dir = TempDir::new("oversized");
    let err = install(&manifest, &dir.0.join("vulns.db"), &mut |_| {}).unwrap_err();
    assert_eq!(err, UpdateError::TooLarge(MAX_DB_BYTES + 1));
}

#[cfg(windows)]
#[test]
fn replacing_an_open_database_says_it_is_in_use() {
    let db = db_bytes(2);
    let base = serve(vec![
        ("/vulns.json", ok(manifest_for(&db, 2))),
        ("/vulns.db", ok(db)),
    ]);
    let dir = TempDir::new("inuse");
    let (dest, before) = existing_db(&dir);
    let open = Database::open(&dest).unwrap();
    let err = update(&format!("{base}/vulns.json"), &dest, &mut |_| {}).unwrap_err();
    assert_eq!(err, UpdateError::InUse);
    drop(open);
    assert_eq!(fs::read(&dest).unwrap(), before);
    assert_eq!(dir.files(), ["vulns.db"]);
}

#[test]
fn manifest_validation() {
    let url = "https://example.com/rel/vulns.json";
    let hash = "AB".repeat(32);
    let good = manifest_json(100, &hash, 7, "vulns.db");
    let m = parse_manifest(good.as_bytes(), url).unwrap();
    assert_eq!(m.db_url, "https://example.com/rel/vulns.db");
    assert_eq!(m.sha256, [0xab; 32]);
    assert_eq!((m.size, m.cve_count), (100, 7));
    let spoof = good.replace(r#""source":"test""#, r#""source":"a\u202eb\u001bc""#);
    let m = parse_manifest(spoof.as_bytes(), url).unwrap();
    assert_eq!(m.source, "a\u{FFFD}b\u{FFFD}c");

    let bad_inputs = [
        "not json".to_string(),
        "{}".to_string(),
        r#"{"schema_version":1}"#.to_string(),
        r#"{"schema_version":0}"#.to_string(),
        r#"{"schema_version":-1}"#.to_string(),
        manifest_json(100, &"ab".repeat(31), 7, "vulns.db"),
        manifest_json(100, &format!("{}g", "a".repeat(63)), 7, "vulns.db"),
        manifest_json(100, &"é".repeat(32), 7, "vulns.db"),
        manifest_json(0, &hash, 7, "vulns.db"),
        manifest_json(100, &hash, 7, ""),
        good.replace("2026-11-01T06:12:00Z", ""),
        good.replace("2026-11-01T06:12:00Z", &"x".repeat(65)),
        good.replace("2026-11-01T06:12:00Z", "a\\u001b[2J"),
        good.replace("2026-11-01T06:12:00Z", "2026\\u202e"),
        good.replace("\"size\":100", "\"size\":-5"),
        good.replace("\"size\":100", "\"size\":\"100\""),
    ];
    for input in &bad_inputs {
        assert!(
            matches!(
                parse_manifest(input.as_bytes(), url),
                Err(UpdateError::BadManifest(_))
            ),
            "{input}"
        );
    }
    let huge = manifest_json(MAX_DB_BYTES as usize + 1, &hash, 7, "vulns.db");
    assert_eq!(
        parse_manifest(huge.as_bytes(), url),
        Err(UpdateError::TooLarge(MAX_DB_BYTES + 1))
    );
}

#[test]
fn url_rules() {
    for ok in [
        "https://github.com/a/b",
        "HTTPS://github.com",
        "https://github.com:443/x?y=1",
        "http://127.0.0.1:8080/x",
        "http://127.5.6.7/x",
        "http://localhost/x",
        "http://[::1]:80/x",
        "https://[2001:db8::1]/x",
    ] {
        assert!(check_url(ok).is_ok(), "{ok}");
    }
    for bad in [
        "http://192.0.2.1/x",
        "http://127.1/x",
        "http://localhost.example.com/x",
        "http://[::2]/x",
        "ftp://example.com/x",
        "javascript://example.com",
        "https://user@example.com/x",
        "https://example.com@127.0.0.1/x",
        "https://evil.com\\@github.com/x",
        "https://exa mple.com/x",
        "https://exämple.com/x",
        "https:///x",
        "https://example.com:x/",
        "https://example.com:/",
        "https://[::1/x",
        "https://[::1]x/",
        "github.com/x",
        "",
    ] {
        assert!(
            matches!(check_url(bad), Err(UpdateError::Insecure(_))),
            "{bad}"
        );
    }
    assert!(check_url(&format!("https://e.com/{}", "a".repeat(MAX_URL_LEN))).is_err());
}

#[test]
fn relative_references_resolve() {
    let base = "https://h.example/a/b/vulns.json?x=1#f";
    assert_eq!(resolve(base, "vulns.db"), "https://h.example/a/b/vulns.db");
    assert_eq!(resolve(base, "/db"), "https://h.example/db");
    assert_eq!(resolve(base, "//cdn.example/db"), "https://cdn.example/db");
    assert_eq!(
        resolve(base, "https://other.example/db"),
        "https://other.example/db"
    );
    assert_eq!(resolve("https://h.example", "db"), "https://h.example/db");
    assert_eq!(resolve("https://h.example?q", "db"), "https://h.example/db");
    // Not absolute: no scheme before the first colon.
    assert_eq!(
        resolve(base, "db?u=http://x"),
        "https://h.example/a/b/db?u=http://x"
    );
}
