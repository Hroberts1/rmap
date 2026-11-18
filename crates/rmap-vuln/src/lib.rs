//! Vulnerability matching (Milestone 4): offline CPE -> CVE lookup against
//! a locally cached, hand-curated starter set of public CVEs.
//!
//! A match is reported as **potentially** vulnerable, never certain: a
//! vendor backport can fix the real bug while leaving the version string
//! unchanged (or bump it in a way this starter set doesn't know about),
//! and a version this set has no data for is not evidence of safety.
//!
//! The database is a text file in an rmap-specific format (see
//! [`db::BUILTIN`] and `cves.txt`), the same style as `rmap-detect`'s
//! `probes.txt`: human-editable, no JSON, and not sourced from Nmap data.

mod db;
pub mod version;

pub use db::{BUILTIN, Bound, CpeMatch, DbError, Entry};
pub use rmap_core::{VulnSeverity, Vulnerability};

/// The database shipped with rmap, parsed once.
pub struct Database {
    entries: Vec<Entry>,
}

impl Database {
    pub fn parse(text: &str) -> Result<Database, DbError> {
        Ok(Database {
            entries: db::parse(text)?,
        })
    }

    /// The database rmap ships, parsed once.
    pub fn builtin() -> Database {
        Database::parse(BUILTIN).unwrap_or_else(|e| panic!("cves.txt {e}"))
    }

    /// Findings whose match criteria cover this CPE 2.3 string, newest
    /// first. An unparseable CPE (not rmap's own output) matches nothing.
    pub fn find(&self, cpe: &str) -> Vec<&Entry> {
        let Some(parsed) = ParsedCpe::parse(cpe) else {
            return Vec::new();
        };
        let mut found: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.matches.iter().any(|m| m.matches(&parsed)))
            .collect();
        found.sort_by(|a, b| b.finding.published.cmp(&a.finding.published));
        found
    }
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
mod tests {
    use super::*;

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
    fn database_finds_a_real_entry_and_nothing_for_an_unknown_cpe() {
        let db = Database::parse(
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
        assert_eq!(
            db.find("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*").len(),
            1
        );
        assert!(
            db.find("cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*:*")
                .is_empty()
        );
        assert!(
            db.find("cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*")
                .is_empty()
        );
        assert!(db.find("garbage").is_empty());
    }

    #[test]
    fn the_real_shipped_database_matches_the_real_cves_it_claims_to() {
        let db = Database::builtin();
        let find = |cpe: &str| {
            db.find(cpe)
                .iter()
                .map(|e| e.finding.id.clone())
                .collect::<Vec<_>>()
        };

        assert_eq!(
            find("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"),
            ["CVE-2024-6387"]
        );
        assert!(find("cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*:*").is_empty());
        assert!(find("cpe:2.3:a:openbsd:openssh:8.4:*:*:*:*:*:*:*").is_empty());

        // 2.4.49 is both the exact path-traversal CVE and inside the
        // broader CONTINUATION-flood range.
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
    }

    #[test]
    fn results_are_sorted_newest_first() {
        let db = Database::parse(
            r#"
cve CVE-2011-0001
  match    acme widget
  severity low
  published 2011-01-01
  summary  "old"

cve CVE-2024-0002
  match    acme widget
  severity low
  published 2024-01-01
  summary  "new"
"#,
        )
        .unwrap();
        let found = db.find("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].finding.id, "CVE-2024-0002");
        assert_eq!(found[1].finding.id, "CVE-2011-0001");
    }
}
