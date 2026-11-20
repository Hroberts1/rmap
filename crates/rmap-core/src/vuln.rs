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
    /// Platform the CVE also needs, from an NVD "running on / with"
    /// configuration, e.g. `musl-libc:musl and linux:linux_kernel`. rmap
    /// can't verify it, so the match is only [`VulnTier::Conditional`].
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub condition: Option<String>,
    /// The CVE is in client programs only (`ssh`, `scp`, ...), so it is
    /// not reachable through a listening port.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "std::ops::Not::not")
    )]
    pub client_only: bool,
}

/// How much a match on a port is worth, most first. Only `Potential` and
/// `UpstreamOnly` count as findings; the others are shown apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VulnTier {
    /// The version is in range and nothing else is needed.
    Potential,
    /// As `Potential`, but the service is a distro build that may carry
    /// backported fixes (the port is [`VulnCheck::CheckedUpstreamOnly`]).
    UpstreamOnly,
    /// Needs a platform rmap can't verify (see `Vulnerability::condition`).
    Conditional,
    /// Client programs only: not counted on a listening port.
    ClientOnly,
}

impl VulnTier {
    pub fn of(v: &Vulnerability, check: Option<&VulnCheck>) -> VulnTier {
        if v.client_only {
            VulnTier::ClientOnly
        } else if v.condition.is_some() {
            VulnTier::Conditional
        } else if matches!(check, Some(VulnCheck::CheckedUpstreamOnly { .. })) {
            VulnTier::UpstreamOnly
        } else {
            VulnTier::Potential
        }
    }

    /// Whether a CISA KEV entry may be flagged as actively exploited: never
    /// for a match whose condition or scope rmap couldn't confirm.
    pub fn shows_kev(self) -> bool {
        matches!(self, VulnTier::Potential | VulnTier::UpstreamOnly)
    }
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
    /// `matches` leaves out conditional and client-only matches.
    Checked {
        product: String,
        version: String,
        matches: u32,
    },
    /// As `Checked`, but the banner names a distro package (`Ubuntu-*`,
    /// `+deb*`, `.el9`, ...): matches are against the upstream version and
    /// `distro` may have backported fixes.
    CheckedUpstreamOnly {
        product: String,
        version: String,
        matches: u32,
        distro: String,
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
        !matches!(
            self,
            VulnCheck::Checked { .. } | VulnCheck::CheckedUpstreamOnly { .. }
        )
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
            VulnCheck::CheckedUpstreamOnly {
                product,
                version,
                matches,
                distro,
            } => match matches {
                0 => write!(f, "no known CVEs for {product} {version} ({distro} build)"),
                n => write!(
                    f,
                    "{n} potential CVE{} ({product} {version}): upstream version; {distro} may have backported fixes",
                    if *n == 1 { "" } else { "s" }
                ),
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
            (
                VulnCheck::CheckedUpstreamOnly {
                    product: "OpenSSH".into(),
                    version: "10.2p1".into(),
                    matches: 2,
                    distro: "Ubuntu".into(),
                },
                "2 potential CVEs (OpenSSH 10.2p1): upstream version; Ubuntu may have backported fixes",
            ),
        ];
        for (check, want) in cases {
            assert_eq!(check.to_string(), want);
            assert_eq!(check.is_unchecked(), want.contains("check"), "{want}");
        }
    }

    #[test]
    fn tiers_put_conditions_and_client_scope_below_findings() {
        let v = |condition: Option<&str>, client_only| Vulnerability {
            id: "CVE-2026-0001".into(),
            summary: String::new(),
            severity: VulnSeverity::High,
            score: None,
            published: None,
            kev_added: Some("2026-01-01".into()),
            condition: condition.map(Into::into),
            client_only,
        };
        let distro = VulnCheck::CheckedUpstreamOnly {
            product: "OpenSSH".into(),
            version: "10.2p1".into(),
            matches: 1,
            distro: "Ubuntu".into(),
        };
        assert_eq!(VulnTier::of(&v(None, false), None), VulnTier::Potential);
        assert_eq!(
            VulnTier::of(&v(None, false), Some(&distro)),
            VulnTier::UpstreamOnly
        );
        let cond = VulnTier::of(&v(Some("musl-libc:musl"), false), Some(&distro));
        assert_eq!(cond, VulnTier::Conditional);
        assert!(!cond.shows_kev());
        let client = VulnTier::of(&v(None, true), None);
        assert_eq!(client, VulnTier::ClientOnly);
        assert!(!client.shows_kev());
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
