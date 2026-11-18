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
}

#[cfg(test)]
mod tests {
    use super::*;

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
