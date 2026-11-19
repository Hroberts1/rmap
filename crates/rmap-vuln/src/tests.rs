use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use rusqlite::Connection;

/// A unique path under the temp dir, deleted (with any SQLite side
/// files) when dropped.
struct TempPath(PathBuf);

impl TempPath {
    fn new(tag: &str) -> TempPath {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        TempPath(
            std::env::temp_dir().join(format!("rmap-vuln-{tag}-{}-{n}.db", std::process::id())),
        )
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("db-journal"));
    }
}

fn inc(v: &str) -> Option<Bound> {
    Some(Bound::Including(v.into()))
}

fn exc(v: &str) -> Option<Bound> {
    Some(Bound::Excluding(v.into()))
}

fn m(vendor: &str, product: &str, min: Option<Bound>, max: Option<Bound>) -> CpeMatch {
    CpeMatch {
        vendor: vendor.into(),
        product: product.into(),
        min,
        max,
    }
}

fn exact(vendor: &str, product: &str, v: &str) -> CpeMatch {
    m(vendor, product, inc(v), inc(v))
}

fn entry(
    id: &str,
    severity: VulnSeverity,
    score: f32,
    published: &str,
    summary: &str,
    matches: Vec<CpeMatch>,
) -> Entry {
    Entry {
        finding: Vulnerability {
            id: id.into(),
            summary: summary.into(),
            severity,
            score: Some(score),
            published: Some(published.into()),
            kev_added: None,
        },
        matches,
    }
}

/// The nine CVEs rmap's old hand-curated text file carried, each verified
/// against nvd.nist.gov when added. Kept as test data.
fn starter_set() -> Vec<Entry> {
    use VulnSeverity::*;
    vec![
        entry(
            "CVE-2024-6387",
            High,
            8.1,
            "2024-07-01",
            "regreSSHion: signal handler race condition in sshd allows unauthenticated remote code execution",
            vec![m("openbsd", "openssh", inc("8.5p1"), inc("9.7p1"))],
        ),
        entry(
            "CVE-2021-41773",
            Critical,
            9.8,
            "2021-10-05",
            "Path traversal in the 2.4.49 path-normalization change",
            vec![exact("apache", "http_server", "2.4.49")],
        ),
        entry(
            "CVE-2024-27316",
            High,
            7.5,
            "2024-04-04",
            "HTTP/2 CONTINUATION flood",
            vec![m("apache", "http_server", inc("2.4.17"), inc("2.4.58"))],
        ),
        entry(
            "CVE-2011-2523",
            Critical,
            9.8,
            "2019-11-27",
            "Trojaned vsftpd 2.3.4 tarball opens a root shell",
            vec![exact("beasts", "vsftpd", "2.3.4")],
        ),
        entry(
            "CVE-2019-10149",
            Critical,
            9.8,
            "2019-06-05",
            "Return to the WIZard: remote command execution in Exim",
            vec![m("exim", "exim", inc("4.87"), inc("4.91"))],
        ),
        entry(
            "CVE-2022-0543",
            Critical,
            10.0,
            "2022-02-18",
            "Debian/Ubuntu-packaging-specific Lua sandbox escape in Redis",
            vec![m("redis", "redis", None, None)],
        ),
        entry(
            "CVE-2013-2028",
            High,
            7.5,
            "2013-07-20",
            "nginx chunked Transfer-Encoding stack buffer overflow",
            vec![m("f5", "nginx", inc("1.3.9"), inc("1.4.0"))],
        ),
        entry(
            "CVE-2015-3306",
            Critical,
            10.0,
            "2015-05-18",
            "ProFTPD mod_copy arbitrary file read and write",
            vec![exact("proftpd", "proftpd", "1.3.5")],
        ),
        entry(
            "CVE-2012-2122",
            Medium,
            5.1,
            "2012-06-26",
            "MySQL/MariaDB memcmp authentication bypass",
            vec![
                m("oracle", "mysql", None, exc("5.1.63")),
                m("oracle", "mysql", inc("5.5"), exc("5.5.24")),
                m("oracle", "mysql", inc("5.6"), exc("5.6.6")),
                m("mariadb", "mariadb", None, exc("5.1.62")),
                m("mariadb", "mariadb", inc("5.2"), exc("5.2.12")),
                m("mariadb", "mariadb", inc("5.3"), exc("5.3.6")),
                m("mariadb", "mariadb", inc("5.5"), exc("5.5.23")),
            ],
        ),
    ]
}

fn build(path: &Path, entries: &[Entry]) {
    let mut w = Writer::create(path).unwrap();
    for e in entries {
        w.add(e).unwrap();
    }
    w.set_meta("built_at", "2026-11-01T00:00:00Z").unwrap();
    w.set_meta("source", "test data").unwrap();
    w.finish().unwrap();
}

fn starter_db() -> (TempPath, Database) {
    let path = TempPath::new("starter");
    build(&path.0, &starter_set());
    let db = Database::open(&path.0).unwrap();
    (path, db)
}

fn ids(db: &Database, cpe: &str) -> Vec<String> {
    db.find(cpe).into_iter().map(|f| f.id).collect()
}

/// Runs SQL against an existing test database, for breaking it on purpose.
fn tamper(path: &Path, sql: &str) {
    Connection::open(path).unwrap().execute_batch(sql).unwrap();
}

#[test]
fn parses_vendor_product_and_combines_version_with_update() {
    let p = ParsedCpe::parse("cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*").unwrap();
    assert_eq!(p.vendor, "openbsd");
    assert_eq!(p.product, "openssh");
    assert_eq!(p.effective_version, "9.7p1");
}

#[test]
fn a_wildcard_update_does_not_get_appended() {
    let p = ParsedCpe::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
    assert_eq!(p.effective_version, "2.4.49");
}

#[test]
fn too_short_a_string_parses_to_nothing() {
    assert!(ParsedCpe::parse("cpe:2.3:a:openbsd").is_none());
    assert!(ParsedCpe::parse("not a cpe at all").is_none());
}

#[test]
fn the_starter_set_matches_the_real_cves_it_claims_to() {
    let (_path, db) = starter_db();
    let find = |cpe: &str| ids(&db, cpe);

    assert_eq!(
        find("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"),
        ["CVE-2024-6387"]
    );
    // Inclusive bounds: both ends of regreSSHion's range match.
    assert_eq!(
        find("cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*").len(),
        1
    );
    assert_eq!(
        find("cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*").len(),
        1
    );
    assert!(find("cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*:*").is_empty());
    assert!(find("cpe:2.3:a:openbsd:openssh:8.4:*:*:*:*:*:*:*").is_empty());

    // 2.4.49 is both the exact path-traversal CVE and inside the broader
    // CONTINUATION-flood range.
    let apache_49 = find("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
    assert!(apache_49.contains(&"CVE-2021-41773".to_string()));
    assert!(apache_49.contains(&"CVE-2024-27316".to_string()));
    assert!(
        !find("cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*")
            .contains(&"CVE-2021-41773".to_string())
    );

    assert_eq!(
        find("cpe:2.3:a:beasts:vsftpd:2.3.4:*:*:*:*:*:*:*"),
        ["CVE-2011-2523"]
    );
    assert!(find("cpe:2.3:a:beasts:vsftpd:2.3.5:*:*:*:*:*:*:*").is_empty());

    // Distro-specific, matches any version.
    assert_eq!(
        find("cpe:2.3:a:redis:redis:7.0:*:*:*:*:*:*:*"),
        ["CVE-2022-0543"]
    );

    // Exclusive upper bounds: the fixed release itself doesn't match.
    assert_eq!(
        find("cpe:2.3:a:oracle:mysql:5.1.50:*:*:*:*:*:*:*"),
        ["CVE-2012-2122"]
    );
    assert!(find("cpe:2.3:a:oracle:mysql:5.1.63:*:*:*:*:*:*:*").is_empty());
    assert_eq!(
        find("cpe:2.3:a:mariadb:mariadb:5.5.10:*:*:*:*:*:*:*"),
        ["CVE-2012-2122"]
    );
    assert!(find("cpe:2.3:a:mariadb:mariadb:5.5.23:*:*:*:*:*:*:*").is_empty());
    assert!(find("cpe:2.3:a:mariadb:mariadb:5.4:*:*:*:*:*:*:*").is_empty());

    assert!(find("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*").is_empty());
    assert!(find("garbage").is_empty());
}

#[test]
fn matching_ignores_cpe_case() {
    let (_path, db) = starter_db();
    assert_eq!(
        ids(&db, "cpe:2.3:a:OpenBSD:OpenSSH:9.6:*:*:*:*:*:*:*"),
        ["CVE-2024-6387"]
    );
}

#[test]
fn findings_carry_every_field_and_come_newest_first() {
    let (_path, db) = starter_db();
    let found = db.find("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].id, "CVE-2024-27316");
    assert_eq!(found[1].id, "CVE-2021-41773");
    assert_eq!(found[1].severity, VulnSeverity::Critical);
    assert_eq!(found[1].score, Some(9.8));
    assert_eq!(found[1].published.as_deref(), Some("2021-10-05"));
    assert_eq!(found[1].kev_added, None);
}

#[test]
fn kev_added_round_trips() {
    let path = TempPath::new("kev");
    let mut e = starter_set().remove(0);
    e.finding.kev_added = Some("2024-07-02".into());
    build(&path.0, &[e.clone()]);
    let db = Database::open(&path.0).unwrap();
    let found = db.find("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*");
    assert_eq!(found, [e.finding]);
}

#[test]
fn info_is_read_at_open() {
    let (_path, db) = starter_db();
    assert_eq!(
        db.info(),
        &DbInfo {
            schema_version: SCHEMA_VERSION,
            built_at: "2026-11-01T00:00:00Z".into(),
            source: "test data".into(),
            cve_count: 9,
        }
    );
}

#[test]
fn knows_product_says_whether_any_row_exists() {
    let (_path, db) = starter_db();
    assert!(db.knows_product("openbsd", "openssh"));
    assert!(db.knows_product("MariaDB", "MariaDB"));
    assert!(!db.knows_product("nginx", "nginx"));
    assert!(!db.knows_product("openbsd", "openssl"));
}

#[test]
fn writer_refuses_to_overwrite_a_file() {
    let path = TempPath::new("exists");
    std::fs::write(&path.0, b"keep me").unwrap();
    assert!(matches!(
        Writer::create(&path.0),
        Err(DbError::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&path.0).unwrap(), b"keep me");
}

#[test]
fn writer_rejects_a_duplicate_id() {
    let path = TempPath::new("dup");
    let mut w = Writer::create(&path.0).unwrap();
    let e = starter_set().remove(0);
    w.add(&e).unwrap();
    assert!(matches!(w.add(&e), Err(DbError::Write(_))));
}

#[test]
fn an_unfinished_writer_leaves_a_file_open_rejects() {
    let path = TempPath::new("unfinished");
    let mut w = Writer::create(&path.0).unwrap();
    w.add(&starter_set().remove(0)).unwrap();
    drop(w);
    assert!(matches!(Database::open(&path.0), Err(DbError::Invalid(_))));
}

#[test]
fn open_reports_a_missing_file() {
    let path = TempPath::new("missing");
    assert!(matches!(Database::open(&path.0), Err(DbError::NotFound)));
}

#[test]
fn open_rejects_a_directory() {
    let dir = std::env::temp_dir();
    assert!(matches!(Database::open(&dir), Err(DbError::Invalid(_))));
}

#[test]
fn open_rejects_empty_random_and_truncated_files_without_panicking() {
    let path = TempPath::new("junk");
    std::fs::write(&path.0, b"").unwrap();
    assert!(matches!(Database::open(&path.0), Err(DbError::Invalid(_))));

    let mut seed: u64 = 0x5EED_CAFE;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for len in [1usize, 100, 4096, 20_000] {
        let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        std::fs::write(&path.0, &junk).unwrap();
        assert!(Database::open(&path.0).is_err(), "{len} random bytes");
    }

    // A real database cut short at several points, and one with garbage
    // written over its pages: opening fails or finds nothing, never panics.
    let good = TempPath::new("good");
    build(&good.0, &starter_set());
    let bytes = std::fs::read(&good.0).unwrap();
    for cut in [16, 100, 512, bytes.len() / 2, bytes.len() - 1] {
        std::fs::write(&path.0, &bytes[..cut]).unwrap();
        if let Ok(db) = Database::open(&path.0) {
            let _ = db.find("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*");
            let _ = db.knows_product("openbsd", "openssh");
        }
    }
    for _ in 0..20 {
        let mut damaged = bytes.clone();
        for _ in 0..64 {
            let at = 100 + (next() as usize) % (damaged.len() - 100);
            damaged[at] = next() as u8;
        }
        std::fs::write(&path.0, &damaged).unwrap();
        if let Ok(db) = Database::open(&path.0) {
            let _ = db.find("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*");
            let _ = db.find("cpe:2.3:a:oracle:mysql:5.1.50:*:*:*:*:*:*:*");
            let _ = db.knows_product("oracle", "mysql");
        }
    }
}

#[test]
fn open_rejects_a_wrong_or_missing_schema_version() {
    let path = TempPath::new("version");
    build(&path.0, &starter_set());
    tamper(
        &path.0,
        "UPDATE meta SET value = '2' WHERE key = 'schema_version'",
    );
    match Database::open(&path.0) {
        Err(DbError::Invalid(msg)) => assert!(msg.contains("schema version 2"), "{msg}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    tamper(&path.0, "DELETE FROM meta WHERE key = 'schema_version'");
    assert!(matches!(Database::open(&path.0), Err(DbError::Invalid(_))));
}

#[test]
fn open_rejects_missing_tables_and_views_in_their_place() {
    let path = TempPath::new("tables");
    build(&path.0, &starter_set());
    tamper(&path.0, "DROP TABLE cpe_match");
    assert!(matches!(Database::open(&path.0), Err(DbError::Invalid(_))));
    tamper(&path.0, "CREATE VIEW cpe_match AS SELECT * FROM cve");
    assert!(matches!(Database::open(&path.0), Err(DbError::Invalid(_))));
}

#[test]
fn hostile_rows_are_skipped_or_cleaned() {
    let path = TempPath::new("hostile");
    build(&path.0, &[]);
    tamper(
        &path.0,
        "INSERT INTO cve VALUES ('CVE-1', 'evil' || char(27) || '[2J' || char(10) || 'x', 'high', 99, 'soon', '2024-01-01');
         INSERT INTO cpe_match VALUES ('CVE-1', 'acme', 'widget', NULL, NULL, NULL, NULL, NULL);
         INSERT INTO cve VALUES ('CVE-2', 'bad severity', 'apocalyptic', 5, NULL, NULL);
         INSERT INTO cpe_match VALUES ('CVE-2', 'acme', 'widget', NULL, NULL, NULL, NULL, NULL);
         INSERT INTO cve VALUES (X'00', 'blob id', 'low', 'nan', NULL, NULL);
         INSERT INTO cpe_match VALUES (X'00', 'acme', 'widget', NULL, NULL, NULL, NULL, NULL);
         INSERT INTO cve VALUES ('CVE-3', 'numeric version', 'low', NULL, NULL, NULL);
         INSERT INTO cpe_match VALUES ('CVE-3', 'acme', 'widget', 42, NULL, NULL, NULL, NULL);",
    );
    let db = Database::open(&path.0).unwrap();
    let found = db.find("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*");
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f.id, "CVE-1");
    assert_eq!(f.summary, "evil\u{FFFD}[2J x");
    assert_eq!(f.score, None);
    assert_eq!(f.published, None);
    assert_eq!(f.kev_added.as_deref(), Some("2024-01-01"));
}

#[test]
fn default_path_ends_in_rmap_vulns_db() {
    if let Some(p) = default_path() {
        assert!(p.ends_with(Path::new("rmap").join("vulns.db")), "{p:?}");
    }
}
