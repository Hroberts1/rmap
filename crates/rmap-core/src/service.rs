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

/// `info` of a TCP port that accepted connections but never sent a byte to
/// any probe (timed out, or closed at once). Its name is the port-table guess.
pub const SILENT_INFO: &str = "connection accepted, no response";

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
    /// Stable identities of the service, used to recognise one device
    /// behind several addresses. Format `<kind> <algorithm>:<value>`, e.g.
    /// `ssh-ed25519 SHA256:<base64, no padding>` (the same text `ssh-keygen -l`
    /// prints) or `tls-cert SHA256:<lowercase hex of the DER certificate>`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub fingerprints: Vec<String>,
    /// The leaf certificate a TLS service presented, when one was parsed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cert: Option<CertInfo>,
}

/// Structured facts about a presented X.509 certificate. Fields the
/// certificate didn't carry (or that failed to parse) are `None`/empty.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    pub sans: Vec<String>,
    pub issuer_cn: Option<String>,
    /// `YYYY-MM-DD` (UTC).
    pub not_before: Option<String>,
    /// `YYYY-MM-DD` (UTC).
    pub not_after: Option<String>,
    /// Subject and issuer are the same name.
    pub self_signed: bool,
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

    /// The name for people to read: a port-number guess ends in `?`
    /// (`weblogic?`), so it doesn't look like an identification.
    pub fn display_name(&self) -> String {
        if self.method == DetectMethod::PortTable && self.name != "unknown" {
            format!("{}?", self.name)
        } else {
            self.name.clone()
        }
    }

    /// Accepted the connection but answered no probe; see [`SILENT_INFO`].
    pub fn is_silent(&self) -> bool {
        self.info.as_deref() == Some(SILENT_INFO)
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

    #[test]
    fn display_name_marks_guesses() {
        let mut s = Service {
            name: "weblogic".into(),
            ..Default::default()
        };
        assert_eq!(s.display_name(), "weblogic?");
        s.method = DetectMethod::Probe;
        assert_eq!(s.display_name(), "weblogic");
        s.method = DetectMethod::PortTable;
        s.name = "unknown".into();
        assert_eq!(s.display_name(), "unknown");
    }
}
