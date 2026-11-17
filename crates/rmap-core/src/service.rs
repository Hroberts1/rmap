//! What service detection learns about a port. Produced by Milestone 3's
//! detector and consumed by the UI, export (Milestone 5) and vulnerability
//! matching (Milestone 4).

/// How a service identification was reached, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum DetectMethod {
    /// Guessed from the port number alone.
    #[default]
    PortTable,
    /// Matched a banner the service sent unprompted.
    Banner,
    /// Matched the reply to a probe rmap sent.
    Probe,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Service {
    /// Protocol-level name: `ssh`, `http`, `smtp`.
    pub name: String,
    /// Software: `OpenSSH`, `nginx`, `Microsoft IIS httpd`.
    pub product: Option<String>,
    /// Version as reported: `8.9p1`, `1.24.0`.
    pub version: Option<String>,
    /// Anything else useful: `Ubuntu Linux; protocol 2.0`.
    pub info: Option<String>,
    /// Operating system the service revealed, if any.
    pub os_hint: Option<String>,
    /// CPE 2.3 identifiers, e.g. `cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*`.
    pub cpes: Vec<String>,
    pub method: DetectMethod,
    /// 0 (guess) to 10 (certain).
    pub confidence: u8,
}

impl Service {
    /// `product version` for display, or `None` if neither is known.
    pub fn version_label(&self) -> Option<String> {
        match (&self.product, &self.version) {
            (Some(p), Some(v)) => Some(format!("{p} {v}")),
            (Some(p), None) => Some(p.clone()),
            (None, Some(v)) => Some(v.clone()),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_label() {
        let mut s = Service {
            name: "ssh".into(),
            ..Default::default()
        };
        assert_eq!(s.version_label(), None);
        s.product = Some("OpenSSH".into());
        assert_eq!(s.version_label().as_deref(), Some("OpenSSH"));
        s.version = Some("9.6p1".into());
        assert_eq!(s.version_label().as_deref(), Some("OpenSSH 9.6p1"));
    }
}
