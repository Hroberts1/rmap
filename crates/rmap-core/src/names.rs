//! Host names learned during a scan, and where each one came from.

use std::fmt;

/// How a host name was learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum NameSource {
    /// Typed by the user as the scan target.
    Target,
    /// Reverse DNS (a PTR record from a DNS server).
    Dns,
    /// The host's NetBIOS name table (UDP 137).
    Netbios,
    /// The host's own mDNS responder (UDP 5353).
    Mdns,
}

impl NameSource {
    /// Short label for display: `DNS`, `NetBIOS`, `mDNS`, `target`.
    pub fn label(self) -> &'static str {
        match self {
            NameSource::Target => "target",
            NameSource::Dns => "DNS",
            NameSource::Netbios => "NetBIOS",
            NameSource::Mdns => "mDNS",
        }
    }
}

impl fmt::Display for NameSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One name for a host. Names come from the network, so `name` is already
/// cleaned of control characters by whoever built it (see `clean`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostName {
    pub name: String,
    pub source: NameSource,
}

impl HostName {
    /// A name from `source`, cleaned with `clean`. `None` if nothing
    /// printable is left.
    pub fn new(name: &str, source: NameSource) -> Option<Self> {
        let name = clean(name);
        (!name.is_empty()).then_some(HostName { name, source })
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.source)
    }
}

/// Longest name kept, in characters (the DNS limit for a full name).
pub const MAX_NAME_LEN: usize = 253;

/// Make a name from the network safe to show and store: trim whitespace
/// and a trailing dot, replace control and other non-printing characters
/// with `?` (they could drive the terminal), and cap the length.
pub fn clean(name: &str) -> String {
    name.trim()
        .trim_end_matches('.')
        .chars()
        .filter(|c| !c.is_whitespace() || *c == ' ')
        .map(|c| if c.is_control() { '?' } else { c })
        .take(MAX_NAME_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_strips_dots_controls_and_length() {
        assert_eq!(clean("host.lan."), "host.lan");
        assert_eq!(clean("  PC-01 \0"), "PC-01 ?");
        assert_eq!(clean("evil\x1b[2Jname"), "evil?[2Jname");
        assert_eq!(clean("tab\there"), "tabhere");
        assert_eq!(clean(&"a".repeat(400)).len(), MAX_NAME_LEN);
        assert_eq!(clean("..."), "");
        assert!(HostName::new(" \n ", NameSource::Dns).is_none());
    }

    #[test]
    fn display() {
        let n = HostName::new("FRONTDESK", NameSource::Netbios).unwrap();
        assert_eq!(n.to_string(), "FRONTDESK (NetBIOS)");
    }
}
