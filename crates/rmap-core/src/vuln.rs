//! What vulnerability matching (Milestone 4) learns about a port. Produced
//! by matching a `Service`'s CPEs against a local CVE database, consumed
//! by the UI and export (Milestone 5).
//!
//! A `Vulnerability` is **potentially** present, not certain: a vendor
//! backport can fix the real bug without changing the version string the
//! CPE carries.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum VulnSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl VulnSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            VulnSeverity::Low => "low",
            VulnSeverity::Medium => "medium",
            VulnSeverity::High => "high",
            VulnSeverity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Vulnerability {
    /// `CVE-YYYY-NNNNN`.
    pub id: String,
    pub summary: String,
    pub severity: VulnSeverity,
    /// CVSS base score, 0.0-10.0, when the database records one.
    pub score: Option<f32>,
    /// `YYYY-MM-DD`, when the database records one.
    pub published: Option<String>,
    /// `YYYY-MM-DD` the CVE was added to CISA's Known Exploited
    /// Vulnerabilities list; `None` if it isn't on it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub kev_added: Option<String>,
}

/// Whether vulnerability matching could check a port, and with what
/// result. Sent for every port that got a `Service` while matching was on,
/// so "no findings" is never mistaken for "checked and clean".
///
/// When a service carries several CPEs, the port gets the most useful
/// outcome among them: `Checked` if any CPE could be looked up, else
/// `VersionHidden`, else `NotCovered`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "status", rename_all = "snake_case")
)]
pub enum VulnCheck {
    /// Looked up; `matches` potential CVEs found (zero means none known).
    Checked {
        product: String,
        version: String,
        matches: u32,
    },
    /// The product was identified but not its version.
    VersionHidden { product: String },
    /// The service is known only by name (or port number), so there is
    /// no product to look up.
    NoProduct,
    /// The CVE data has nothing on this product.
    NotCovered { product: String },
    /// Matching was on but no usable CVE database was found.
    NoDatabase,
}

impl VulnCheck {
    /// Every outcome except `Checked`: the port was not looked up.
    pub fn is_unchecked(&self) -> bool {
        !matches!(self, VulnCheck::Checked { .. })
    }
}

impl std::fmt::Display for VulnCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnCheck::Checked {
                product,
                version,
                matches,
            } => match matches {
                0 => write!(f, "no known CVEs for {product} {version}"),
                1 => write!(f, "1 potential CVE ({product} {version})"),
                n => write!(f, "{n} potential CVEs ({product} {version})"),
            },
            VulnCheck::VersionHidden { product } => {
                write!(f, "{product} detected, version unknown: can't check")
            }
            VulnCheck::NoProduct => f.write_str("product not identified: can't check"),
            VulnCheck::NotCovered { product } => {
                write!(f, "no CVE data for {product}: not checked")
            }
            VulnCheck::NoDatabase => f.write_str("no vulnerability data: not checked"),
        }
    }
}

/// Which CVE database a scan matched against, so readers can judge how
/// current its findings are.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VulnData {
    /// When the database was built, as recorded in it; starts `YYYY-MM-DD`.
    pub built_at: String,
    pub cve_count: u64,
    /// Where its data came from.
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_labels() {
        let checked = |version: &str, matches| VulnCheck::Checked {
            product: "nginx".into(),
            version: version.into(),
            matches,
        };
        let product = || "nginx".to_string();
        let cases = [
            (checked("1.24.0", 0), "no known CVEs for nginx 1.24.0"),
            (checked("1.24.0", 1), "1 potential CVE (nginx 1.24.0)"),
            (checked("1.24.0", 2), "2 potential CVEs (nginx 1.24.0)"),
            (
                VulnCheck::VersionHidden { product: product() },
                "nginx detected, version unknown: can't check",
            ),
            (VulnCheck::NoProduct, "product not identified: can't check"),
            (
                VulnCheck::NotCovered { product: product() },
                "no CVE data for nginx: not checked",
            ),
            (VulnCheck::NoDatabase, "no vulnerability data: not checked"),
        ];
        for (check, want) in cases {
            assert_eq!(check.to_string(), want);
            assert_eq!(check.is_unchecked(), want.contains("check"), "{want}");
        }
    }

    #[test]
    fn severity_as_str() {
        assert_eq!(VulnSeverity::Critical.as_str(), "critical");
        assert_eq!(VulnSeverity::Low.as_str(), "low");
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(VulnSeverity::Low < VulnSeverity::Medium);
        assert!(VulnSeverity::Medium < VulnSeverity::High);
        assert!(VulnSeverity::High < VulnSeverity::Critical);
    }
}
