use std::path::PathBuf;

use super::*;
use rmap_core::Service;
use serde_json::json;

fn products() -> Products {
    rmap_detect::cpe::nvd_products()
        .map(|(v, p)| (v.to_string(), p.to_string()))
        .collect()
}

fn inc(v: &str) -> Option<Bound> {
    Some(Bound::Including(v.into()))
}

fn exc(v: &str) -> Option<Bound> {
    Some(Bound::Excluding(v.into()))
}

fn range(vendor: &str, product: &str, min: Option<Bound>, max: Option<Bound>) -> CpeMatch {
    CpeMatch {
        vendor: vendor.into(),
        product: product.into(),
        min,
        max,
    }
}

/// A cpeMatch object for `criteria` plus extra fields.
fn cm(criteria: &str, extra: Value) -> Value {
    let mut m = json!({"vulnerable": true, "criteria": criteria});
    if let (Some(m), Some(extra)) = (m.as_object_mut(), extra.as_object()) {
        m.extend(extra.clone());
    }
    m
}

fn one(m: Value) -> Option<CpeMatch> {
    cpe_match(&m)
}

/// A CVE with one OR node holding `matches`.
fn cve(id: &str, matches: Vec<Value>, metrics: Value) -> Value {
    json!({
        "id": id,
        "vulnStatus": "Analyzed",
        "published": "2024-07-01T13:15:06.467",
        "lastModified": "2024-08-01T00:00:00.000",
        "descriptions": [
            {"lang": "es", "value": "Una condicion de carrera"},
            {"lang": "en", "value": "  A signal handler\n race condition in sshd.  "}
        ],
        "metrics": metrics,
        "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": matches}]}]
    })
}

fn v31(sev: &str, score: f64) -> Value {
    json!({"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": sev}}]})
}

#[test]
fn ranges_map_to_bounds() {
    let c = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*";
    assert_eq!(
        one(cm(
            c,
            json!({"versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"})
        )),
        Some(range("openbsd", "openssh", inc("8.5p1"), exc("9.8p1")))
    );
    assert_eq!(
        one(cm(
            c,
            json!({"versionStartExcluding": "1.0", "versionEndIncluding": "2.0"})
        )),
        Some(range("openbsd", "openssh", exc("1.0"), inc("2.0")))
    );
    assert_eq!(
        one(cm(c, json!({"versionEndExcluding": "4.4"}))),
        Some(range("openbsd", "openssh", None, exc("4.4")))
    );
}

#[test]
fn exact_versions_combine_version_and_update() {
    let exact = |v: &str| Some(range("openbsd", "openssh", inc(v), inc(v)));
    assert_eq!(
        one(cm(
            "cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*",
            json!({})
        )),
        exact("9.7p1")
    );
    assert_eq!(
        one(cm("cpe:2.3:a:openbsd:openssh:9.6:-:*:*:*:*:*:*", json!({}))),
        exact("9.6")
    );
    assert_eq!(
        one(cm("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", json!({}))),
        exact("9.6")
    );
    // Upper case and needless escapes are normalised to rmap-detect's form.
    assert_eq!(
        one(cm(
            "cpe:2.3:a:OpenBSD:OpenSSH:9\\.7:P1:*:*:*:*:*:*",
            json!({})
        )),
        exact("9.7p1")
    );
}

#[test]
fn any_and_not_applicable_versions() {
    // "*" alone: every version, stored with no bounds.
    assert_eq!(
        one(cm("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", json!({}))),
        Some(range("f5", "nginx", None, None))
    );
    assert_eq!(
        one(cm("cpe:2.3:a:f5:nginx:-:*:*:*:*:*:*:*", json!({}))),
        None
    );
    assert_eq!(
        one(cm("cpe:2.3:a:f5:nginx:*:beta:*:*:*:*:*:*", json!({}))),
        None
    );
}

#[test]
fn unusable_matches_are_skipped() {
    let ok = "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*";
    assert!(one(cm(ok, json!({}))).is_some());
    assert_eq!(
        cpe_match(&json!({"vulnerable": false, "criteria": ok})),
        None
    );
    assert_eq!(
        cpe_match(&json!({"vulnerable": "true", "criteria": ok})),
        None
    );
    assert_eq!(cpe_match(&json!({"vulnerable": true})), None);
    assert_eq!(cpe_match(&json!({"vulnerable": true, "criteria": 5})), None);
    for bad in [
        "",
        "cpe:2.3:a:f5:nginx",
        "cpe:2.2:a:f5:nginx:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:x:f5:nginx:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:f5:nginx:1.0\\",
        "cpe:2.3:a:f5:nginx:\u{e9}:*:*:*:*:*:*:*",
    ] {
        assert_eq!(one(cm(bad, json!({}))), None, "{bad:?}");
    }
    // A bound of the wrong type, or empty, must not widen the range.
    let any = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*";
    assert_eq!(one(cm(any, json!({"versionEndExcluding": 1.2}))), None);
    assert_eq!(one(cm(any, json!({"versionEndExcluding": ""}))), None);
    assert_eq!(
        one(cm(any, json!({"versionEndExcluding": "x".repeat(10_000)}))),
        None
    );
    assert_eq!(
        one(cm(
            &format!("cpe:2.3:a:f5:nginx:{}", "1".repeat(5000)),
            json!({})
        )),
        None
    );
}

#[test]
fn cpe_escapes() {
    assert_eq!(
        split_cpe("cpe:2.3:a:a\\:b:c\\\\d:1\\*:*").unwrap(),
        ["cpe", "2.3", "a", "a\\:b", "c\\\\d", "1\\*", "*"]
    );
    assert_eq!(unescape("a\\:b\\\\c\\.d"), "a:b\\c.d");
    assert_eq!(unescape("trailing\\"), "trailing\\");
    // A literal "*" in a version keeps its escape, as rmap-detect writes it.
    assert_eq!(
        one(cm(
            "cpe:2.3:a:digium:asterisk:18.10.0\\~dfsg:*:*:*:*:*:*:*",
            json!({})
        )),
        Some(range(
            "digium",
            "asterisk",
            inc("18.10.0\\~dfsg"),
            inc("18.10.0\\~dfsg")
        ))
    );
    assert_eq!(
        one(cm("cpe:2.3:a:f5:nginx:\\*:*:*:*:*:*:*:*", json!({}))),
        Some(range("f5", "nginx", inc("\\*"), inc("\\*")))
    );
}

#[test]
fn cve_conversion() {
    let kev = HashMap::from([("CVE-2024-6387".to_string(), "2024-07-10".to_string())]);
    let c = cve(
        "CVE-2024-6387",
        vec![
            cm(
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                json!({"versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"}),
            ),
            // Duplicate, not vulnerable, and undetectable products drop out.
            cm(
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                json!({"versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"}),
            ),
            json!({"vulnerable": false, "criteria": "cpe:2.3:a:openbsd:openssh:4.3:*:*:*:*:*:*:*"}),
            cm("cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*", json!({})),
        ],
        v31("HIGH", 8.1),
    );
    let e = convert_cve(&c, &products(), &kev).unwrap();
    assert_eq!(e.finding.id, "CVE-2024-6387");
    assert_eq!(
        e.finding.summary,
        "A signal handler race condition in sshd."
    );
    assert_eq!(e.finding.severity, VulnSeverity::High);
    assert_eq!(e.finding.score, Some(8.1));
    assert_eq!(e.finding.published.as_deref(), Some("2024-07-01"));
    assert_eq!(e.finding.kev_added.as_deref(), Some("2024-07-10"));
    assert_eq!(
        e.matches,
        [range("openbsd", "openssh", inc("8.5p1"), exc("9.8p1"))]
    );

    let undetectable = cve(
        "CVE-2024-0001",
        vec![cm("cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*", json!({}))],
        json!({}),
    );
    assert!(convert_cve(&undetectable, &products(), &kev).is_none());

    let mut rejected = c.clone();
    rejected["vulnStatus"] = json!("Rejected");
    assert!(convert_cve(&rejected, &products(), &kev).is_none());
}

#[test]
fn and_configurations_keep_the_vulnerable_app() {
    let c = json!({
        "id": "CVE-2020-0001",
        "configurations": [{"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [cm("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", json!({}))]},
            {"operator": "OR", "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]},
            {"negate": true, "cpeMatch": [cm("cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*", json!({}))]}
        ]}]
    });
    let e = convert_cve(&c, &products(), &HashMap::new()).unwrap();
    assert_eq!(
        e.matches,
        [range("apache", "http_server", inc("2.4.49"), inc("2.4.49"))]
    );
}

#[test]
fn severity_preference_and_fallbacks() {
    let sev = |m: Value| severity(Some(&m));
    let both = json!({
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
        ],
        "cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]
    });
    assert_eq!(sev(both), Some((VulnSeverity::Critical, Some(9.8))));
    assert_eq!(
        sev(
            json!({"cvssMetricV30": [{"type": "Secondary", "cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"}}]})
        ),
        Some((VulnSeverity::Low, Some(3.1)))
    );
    // v2 keeps its own rating (no "critical" in v2).
    assert_eq!(
        sev(
            json!({"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"baseScore": 10.0}}]})
        ),
        Some((VulnSeverity::High, Some(10.0)))
    );
    assert_eq!(
        sev(
            json!({"cvssMetricV40": [{"type": "Secondary", "cvssData": {"baseScore": 0.0, "baseSeverity": "NONE"}}]})
        ),
        Some((VulnSeverity::Low, Some(0.0)))
    );
    // Score without a rating: banded; rating without a usable score: kept.
    assert_eq!(
        sev(json!({"cvssMetricV31": [{"cvssData": {"baseScore": 7.0}}]})),
        Some((VulnSeverity::High, Some(7.0)))
    );
    assert_eq!(
        sev(json!({"cvssMetricV31": [{"cvssData": {"baseScore": 99, "baseSeverity": "high"}}]})),
        Some((VulnSeverity::High, None))
    );
    // Garbage falls through to the next version, then to nothing.
    assert_eq!(
        sev(
            json!({"cvssMetricV31": [{"cvssData": {"baseSeverity": "WILD"}}], "cvssMetricV2": "x"})
        ),
        None
    );
    assert_eq!(sev(json!({})), None);
    assert_eq!(severity(None), None);
    assert_eq!(sev(json!([1, 2])), None);
}

#[test]
fn cves_without_metrics_get_a_placeholder_severity() {
    let c = cve(
        "CVE-2025-0002",
        vec![cm("cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*", json!({}))],
        json!({}),
    );
    let none = HashMap::new();
    let e = convert_cve(&c, &products(), &none).unwrap();
    assert_eq!(
        (e.finding.severity, e.finding.score),
        (VulnSeverity::Medium, None)
    );
    let kev = HashMap::from([("CVE-2025-0002".to_string(), "2025-01-01".to_string())]);
    let e = convert_cve(&c, &products(), &kev).unwrap();
    assert_eq!(
        (e.finding.severity, e.finding.score),
        (VulnSeverity::High, None)
    );
}

#[test]
fn summaries_are_capped() {
    let mut c = cve(
        "CVE-2025-0003",
        vec![cm("cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*", json!({}))],
        json!({}),
    );
    c["descriptions"] = json!([{"lang": "en", "value": "\u{e9}".repeat(100_000)}]);
    let s = convert_cve(&c, &products(), &HashMap::new())
        .unwrap()
        .finding
        .summary;
    assert_eq!(s.chars().count(), MAX_SUMMARY);
    assert!(s.ends_with("..."));
    c["descriptions"] = json!("nope");
    let s = convert_cve(&c, &products(), &HashMap::new())
        .unwrap()
        .finding
        .summary;
    assert_eq!(s, "(no description)");
}

#[test]
fn malformed_cves_never_panic() {
    let p = products();
    let k = HashMap::new();
    let nginx = cm("cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*", json!({}));
    for bad in [
        json!(null),
        json!([]),
        json!("CVE-2024-1"),
        json!({"id": 5}),
        json!({"id": "GHSA-1234", "configurations": [{"nodes": [{"cpeMatch": [nginx.clone()]}]}]}),
        json!({"id": "CVE-2024-1"}),
        json!({"id": "CVE-2024-1", "configurations": "x"}),
        json!({"id": "CVE-2024-1", "configurations": [{"nodes": 7}]}),
        json!({"id": "CVE-2024-1", "configurations": [{"nodes": [{"cpeMatch": [null, 1, "x"]}]}]}),
        json!({"id": format!("CVE-{}", "9".repeat(100)), "configurations": [{"nodes": [{"cpeMatch": [nginx.clone()]}]}]}),
    ] {
        assert!(convert_cve(&bad, &p, &k).is_none(), "{bad}");
    }
    // Wrong-typed optional fields are dropped, not the CVE.
    let odd = json!({
        "id": "CVE-2024-2", "published": 2024, "metrics": "x", "descriptions": [{"lang": "en", "value": 3}],
        "configurations": [{"nodes": [{"cpeMatch": [nginx]}]}]
    });
    let e = convert_cve(&odd, &p, &k).unwrap();
    assert_eq!(e.finding.published, None);
    assert_eq!(e.finding.summary, "(no description)");
}

#[test]
fn pages_and_kev() {
    let page = json!({
        "resultsPerPage": 2, "startIndex": 0, "totalResults": 10,
        "vulnerabilities": [
            {"cve": cve("CVE-2024-6387", vec![cm("cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*", json!({}))], v31("HIGH", 8.1))},
            {"cve": {"id": "CVE-2024-9", "lastModified": "2025-01-02T00:00:00.000"}},
            "junk"
        ]
    });
    let p = convert_page(&page, &products(), &HashMap::new()).unwrap();
    assert_eq!((p.total_results, p.returned, p.entries.len()), (10, 3, 1));
    assert_eq!(p.ids, ["CVE-2024-6387", "CVE-2024-9"], "kept or not");
    assert_eq!(p.last_modified.as_deref(), Some("2025-01-02T00:00:00.000"));
    assert!(
        convert_page(
            &json!({"message": "rate limited"}),
            &products(),
            &HashMap::new()
        )
        .is_none()
    );
    assert!(
        convert_page(
            &json!({"totalResults": "10", "vulnerabilities": []}),
            &products(),
            &HashMap::new()
        )
        .is_none()
    );

    let kev = kev_dates(&json!({"vulnerabilities": [
        {"cveID": "CVE-2024-6387", "dateAdded": "2024-07-10"},
        {"cveID": "CVE-2024-1", "dateAdded": "July"},
        {"cveID": 7, "dateAdded": "2024-07-10"},
        {"cveID": "", "dateAdded": "2024-07-10"},
        null
    ]}));
    assert_eq!(kev.len(), 1);
    assert_eq!(kev["CVE-2024-6387"], "2024-07-10");
    assert!(kev_dates(&json!({"vulnerabilities": {}})).is_empty());
    assert_eq!(
        date_part("2024-07-01T13:15:06.467").as_deref(),
        Some("2024-07-01")
    );
    assert_eq!(date_part("2024-7-1"), None);
    assert_eq!(date_part("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"), None);
}

/// End to end: converted entries written with `Writer` are found by
/// `Database::find` for the CPEs rmap-detect actually generates.
#[test]
fn converted_entries_match_rmap_detect_cpes() {
    let path: PathBuf =
        std::env::temp_dir().join(format!("vulndb-build-test-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let entries = [
        cve(
            "CVE-2024-6387",
            vec![cm(
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                json!({"versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"}),
            )],
            v31("HIGH", 8.1),
        ),
        cve(
            "CVE-2016-0777",
            vec![cm(
                "cpe:2.3:a:openbsd:openssh:7.1:p1:*:*:*:*:*:*",
                json!({}),
            )],
            v31("MEDIUM", 6.5),
        ),
    ];
    let result = (|| {
        let mut w = rmap_vuln::Writer::create(&path)?;
        for c in &entries {
            w.add(&convert_cve(c, &products(), &HashMap::new()).unwrap())?;
        }
        w.finish()?;
        rmap_vuln::Database::open(&path)
    })();
    let ids = |db: &rmap_vuln::Database, version: &str| -> Vec<String> {
        let service = Service {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: Some(version.into()),
            ..Default::default()
        };
        let cpe = rmap_detect::cpe::for_service(&service).pop().unwrap();
        db.find(&cpe).into_iter().map(|f| f.id).collect()
    };
    let checks = result.map(|db| {
        (
            ids(&db, "9.6p1"),
            ids(&db, "9.8p1"),
            ids(&db, "7.1p1"),
            ids(&db, "7.1p2"),
        )
    });
    let _ = std::fs::remove_file(&path);
    let (a, b, c, d) = checks.unwrap();
    assert_eq!(a, ["CVE-2024-6387"]);
    assert!(b.is_empty());
    assert_eq!(c, ["CVE-2016-0777"]);
    assert!(d.is_empty());
}
