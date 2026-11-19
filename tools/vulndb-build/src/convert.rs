//! NVD API 2.0 and CISA KEV JSON -> `rmap_vuln::Entry`. Pure functions:
//! the JSON is untrusted, so anything that doesn't fit the expected shape
//! is skipped (a field, a match, a CVE), never a panic.
//!
//! Versions are stored the way `rmap-detect` writes them into CPEs and
//! `rmap_vuln`'s `ParsedCpe` reads them back: CPE 2.3 formatted-string
//! form (reserved characters other than `.` `-` `_` keep their backslash,
//! lowercase) with the `update` field appended (`9.7` + `p1` -> `9.7p1`).

use std::collections::{HashMap, HashSet};

use rmap_core::{VulnSeverity, Vulnerability};
use rmap_detect::cpe::escape;
use rmap_vuln::{Bound, CpeMatch, Entry};
use serde_json::Value;

/// Longest summary kept, in characters (NVD descriptions can run to pages).
const MAX_SUMMARY: usize = 1000;
const MAX_ID: usize = 64;

/// NVD (vendor, product) pairs rmap can detect, lowercase.
pub type Products = HashSet<(String, String)>;

/// CVE id -> date (`YYYY-MM-DD`) it was added to CISA KEV.
pub fn kev_dates(json: &Value) -> HashMap<String, String> {
    let Some(list) = json.get("vulnerabilities").and_then(Value::as_array) else {
        return HashMap::new();
    };
    list.iter()
        .filter_map(|v| {
            let id = v.get("cveID")?.as_str()?.trim();
            let date = date_part(v.get("dateAdded")?.as_str()?)?;
            (!id.is_empty() && id.len() <= MAX_ID).then(|| (id.to_string(), date))
        })
        .collect()
}

/// One page of `/rest/json/cves/2.0`.
#[derive(Debug, Default)]
pub struct Page {
    pub total_results: u64,
    /// CVEs on the page, before filtering (to advance `startIndex`).
    pub returned: usize,
    pub entries: Vec<Entry>,
    /// Newest `lastModified` on the page.
    pub last_modified: Option<String>,
}

/// `None` when the JSON isn't an NVD CVE page at all.
pub fn convert_page(
    json: &Value,
    products: &Products,
    kev: &HashMap<String, String>,
) -> Option<Page> {
    let total_results = json.get("totalResults")?.as_u64()?;
    let list = json.get("vulnerabilities")?.as_array()?;
    let cves = list.iter().filter_map(|v| v.get("cve"));
    let last_modified = cves
        .clone()
        .filter_map(|c| c.get("lastModified")?.as_str())
        .filter(|s| s.len() <= 40)
        .max()
        .map(str::to_string);
    Some(Page {
        total_results,
        returned: list.len(),
        entries: cves.filter_map(|c| convert_cve(c, products, kev)).collect(),
        last_modified,
    })
}

/// A CVE as an `Entry`, or `None` when it is rejected, malformed, or
/// affects no product rmap detects.
pub fn convert_cve(
    cve: &Value,
    products: &Products,
    kev: &HashMap<String, String>,
) -> Option<Entry> {
    let id = cve.get("id")?.as_str()?.trim();
    if !id.starts_with("CVE-") || id.len() > MAX_ID {
        return None;
    }
    if cve.get("vulnStatus").and_then(Value::as_str) == Some("Rejected") {
        return None;
    }
    let mut matches: Vec<CpeMatch> = Vec::new();
    let nodes = array(cve, "configurations")
        .flat_map(|c| array(c, "nodes"))
        // A negated node lists what is *not* affected.
        .filter(|n| n.get("negate").and_then(Value::as_bool) != Some(true));
    // AND configurations ("X running on Y") keep X's match: rmap can't
    // verify the platform, so this can over-report.
    for m in nodes.flat_map(|n| array(n, "cpeMatch")) {
        if let Some(m) =
            cpe_match(m).filter(|m| products.contains(&(m.vendor.clone(), m.product.clone())))
            && !matches.contains(&m)
        {
            matches.push(m);
        }
    }
    if matches.is_empty() {
        return None;
    }
    let kev_added = kev.get(id).cloned();
    // No CVSS data (common for NVD's backlog): keep the CVE, with no score
    // and a placeholder severity - High if it is known to be exploited.
    let (severity, score) = severity(cve.get("metrics")).unwrap_or(if kev_added.is_some() {
        (VulnSeverity::High, None)
    } else {
        (VulnSeverity::Medium, None)
    });
    Some(Entry {
        finding: Vulnerability {
            id: id.to_string(),
            summary: summary(cve),
            severity,
            score,
            published: cve
                .get("published")
                .and_then(Value::as_str)
                .and_then(date_part),
            kev_added,
        },
        matches,
    })
}

fn array<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> + Clone {
    v.get(key).and_then(Value::as_array).into_iter().flatten()
}

/// The English description, whitespace collapsed, capped.
fn summary(cve: &Value) -> String {
    let text = array(cve, "descriptions")
        .find(|d| d.get("lang").and_then(Value::as_str) == Some("en"))
        .and_then(|d| d.get("value")?.as_str())
        .unwrap_or("");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        "(no description)".into()
    } else if text.chars().count() > MAX_SUMMARY {
        text.chars().take(MAX_SUMMARY - 3).collect::<String>() + "..."
    } else {
        text
    }
}

/// Severity and base score from the preferred CVSS version: v3.1, v3.0,
/// v4.0, then v2. Within a version the `Primary` (NVD's own) metric wins.
fn severity(metrics: Option<&Value>) -> Option<(VulnSeverity, Option<f32>)> {
    let metrics = metrics?;
    for key in [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV40",
        "cvssMetricV2",
    ] {
        let list: Vec<&Value> = array(metrics, key).collect();
        let Some(m) = list
            .iter()
            .find(|m| m.get("type").and_then(Value::as_str) == Some("Primary"))
            .or(list.first())
        else {
            continue;
        };
        let data = m.get("cvssData");
        let score = data
            .and_then(|d| d.get("baseScore")?.as_f64())
            .filter(|s| (0.0..=10.0).contains(s))
            .map(|s| s as f32);
        // v3/v4 keep the rating in cvssData, v2 next to it. v2 has no
        // "critical": its LOW/MEDIUM/HIGH are kept as NVD rated them.
        let named = data
            .and_then(|d| d.get("baseSeverity"))
            .or(m.get("baseSeverity"))
            .and_then(Value::as_str)
            .and_then(|s| {
                Some(match s.to_ascii_lowercase().as_str() {
                    "critical" => VulnSeverity::Critical,
                    "high" => VulnSeverity::High,
                    "medium" => VulnSeverity::Medium,
                    "low" | "none" => VulnSeverity::Low,
                    _ => return None,
                })
            });
        if let Some(sev) = named.or(score.map(band)) {
            return Some((sev, score));
        }
    }
    None
}

/// CVSS v3 qualitative rating for a score.
fn band(score: f32) -> VulnSeverity {
    match score {
        s if s >= 9.0 => VulnSeverity::Critical,
        s if s >= 7.0 => VulnSeverity::High,
        s if s >= 4.0 => VulnSeverity::Medium,
        _ => VulnSeverity::Low,
    }
}

/// One `cpeMatch` object as a range, or `None` if it isn't vulnerable,
/// isn't a usable CPE, or has a version rmap can't encode.
fn cpe_match(m: &Value) -> Option<CpeMatch> {
    if m.get("vulnerable").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let fields = split_cpe(m.get("criteria")?.as_str()?)?;
    let [cpe, ver, part, vendor, product, version, update, ..] = fields.as_slice() else {
        return None;
    };
    if cpe != "cpe" || ver != "2.3" || !matches!(part.as_str(), "a" | "o" | "h") {
        return None;
    }
    let (vendor, product) = (
        unescape(vendor).to_lowercase(),
        unescape(product).to_lowercase(),
    );
    let range = |key: &str| -> Option<Option<String>> {
        match m.get(key) {
            None | Some(Value::Null) => Some(None),
            // A bound that is there but unusable must not widen the range.
            Some(v) => Some(Some(fs_version(v.as_str()?)?)),
        }
    };
    let start = match (
        range("versionStartIncluding")?,
        range("versionStartExcluding")?,
    ) {
        (Some(v), _) => Some(Bound::Including(v)),
        (None, Some(v)) => Some(Bound::Excluding(v)),
        (None, None) => None,
    };
    let end = match (range("versionEndIncluding")?, range("versionEndExcluding")?) {
        (Some(v), _) => Some(Bound::Including(v)),
        (None, Some(v)) => Some(Bound::Excluding(v)),
        (None, None) => None,
    };
    let (min, max) = if start.is_some() || end.is_some() {
        (start, end)
    } else {
        match (version.as_str(), update.as_str()) {
            // "-": not applicable, nothing to compare against.
            ("-", _) => return None,
            // "*" with no range: NVD says every version is affected, and
            // rmap_vuln matches a row with no bounds against any version.
            ("*", "*" | "-") => (None, None),
            // Any version but only one update: not expressible as a range.
            ("*", _) => return None,
            (v, u) => {
                let mut exact = fs_version(&unescape(v))?;
                if u != "*" && u != "-" {
                    exact.push_str(&fs_version(&unescape(u))?);
                }
                (
                    Some(Bound::Including(exact.clone())),
                    Some(Bound::Including(exact)),
                )
            }
        }
    };
    Some(CpeMatch {
        vendor,
        product,
        min,
        max,
    })
}

/// A version in the form rmap-detect writes it, or `None` if nothing
/// usable is left.
fn fs_version(raw: &str) -> Option<String> {
    let v = escape(raw);
    (v != "*" && v.len() <= 100).then_some(v)
}

/// Splits a CPE 2.3 formatted string on unescaped colons; the fields keep
/// their backslash escapes so `*` (any) and `\*` (a literal) stay distinct.
fn split_cpe(s: &str) -> Option<Vec<String>> {
    if s.len() > 1000 {
        return None;
    }
    let mut fields = vec![String::new()];
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let next = chars.next()?;
                let f = fields.last_mut()?;
                f.push('\\');
                f.push(next);
            }
            ':' => fields.push(String::new()),
            c => fields.last_mut()?.push(c),
        }
    }
    Some(fields)
}

/// Drops CPE 2.3 backslash escapes (`\:` -> `:`, `\\` -> `\`).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' {
            chars.next().unwrap_or('\\')
        } else {
            c
        });
    }
    out
}

/// `2024-07-01T12:00:00.000` -> `2024-07-01`; `None` unless it starts with
/// a `YYYY-MM-DD` date.
fn date_part(s: &str) -> Option<String> {
    let d = s.get(..10)?;
    let ok = d.bytes().enumerate().all(|(i, b)| match i {
        4 | 7 => b == b'-',
        _ => b.is_ascii_digit(),
    });
    ok.then(|| d.to_string())
}

#[cfg(test)]
mod tests;
