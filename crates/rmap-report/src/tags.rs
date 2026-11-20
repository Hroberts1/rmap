//! Host tags: conclusions about a whole host drawn from its ports, written
//! to `HostReport::tags` with the evidence in `tag_reasons`.

use std::net::IpAddr;

use rmap_core::{
    DetectMethod, MacAddr, PortResult, PortState, Protocol, client_speaks_first, is_print_port,
};

use crate::HostReport;

/// Many unrelated ports accept connections and none says anything: a
/// decoy (UniFi Honeypot, a tarpit) or something answering for the host.
pub const LIKELY_HONEYPOT: &str = "likely_honeypot_or_tarpit";

/// Fewest quiet ports that earn the tag.
const MIN_QUIET: usize = 5;
/// Most "same MAC as" addresses listed.
const MAX_SAME_MAC: usize = 3;

/// The evidence for [`LIKELY_HONEYPOT`], or nothing when the host doesn't
/// fit: at least five open TCP ports and every one of them silent or
/// banner-less. Print ports and protocols where the client speaks first
/// are ignored, since silence there is normal. `others` are the other up
/// hosts; sharing a MAC with one is typical of a decoy on a gateway.
pub fn honeypot_reasons(
    ip: IpAddr,
    ports: &[PortResult],
    mac: Option<MacAddr>,
    others: impl IntoIterator<Item = (IpAddr, Option<MacAddr>)>,
) -> Vec<String> {
    let counted: Vec<&PortResult> = ports
        .iter()
        .filter(|p| p.state == PortState::Open && p.protocol == Protocol::Tcp)
        .filter(|p| !is_print_port(p.port) && !client_speaks_first(p.port))
        .collect();
    let quiet = |p: &&PortResult| match &p.service {
        None => true,
        Some(s) => s.is_silent() || (s.method == DetectMethod::PortTable && s.info.is_none()),
    };
    if counted.len() < MIN_QUIET || !counted.iter().all(quiet) {
        return Vec::new();
    }
    let mut reasons = vec![format!(
        "{} ports accept connections but send nothing",
        counted.len()
    )];
    if let Some(mac) = mac {
        let same: Vec<String> = others
            .into_iter()
            .filter(|&(other, m)| other != ip && m == Some(mac))
            .map(|(other, _)| other.to_string())
            .take(MAX_SAME_MAC)
            .collect();
        if !same.is_empty() {
            reasons.push(format!("same MAC as {}", same.join(", ")));
        }
    }
    reasons
}

/// Recompute every host's tags from its ports and the other up hosts.
pub fn tag_hosts(hosts: &mut [HostReport]) {
    let up: Vec<(IpAddr, Option<MacAddr>)> = hosts
        .iter()
        .filter(|h| h.is_up())
        .map(|h| (h.ip, h.mac))
        .collect();
    for h in hosts.iter_mut() {
        h.tags.clear();
        h.tag_reasons = if h.is_up() {
            honeypot_reasons(h.ip, &h.ports, h.mac, up.iter().copied())
        } else {
            Vec::new()
        };
        if !h.tag_reasons.is_empty() {
            h.tags.push(LIKELY_HONEYPOT.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use rmap_core::{HostState, SILENT_INFO, Service};

    use super::*;

    fn port(port: u16, service: Option<Service>) -> PortResult {
        let mut p = PortResult::new(port, Protocol::Tcp, PortState::Open, None);
        p.service = service;
        p
    }

    fn silent(port: u16) -> PortResult {
        let name = rmap_core::service_name(port).unwrap_or("unknown");
        self::port(
            port,
            Some(Service {
                name: name.into(),
                info: Some(SILENT_INFO.into()),
                confidence: 1,
                ..Default::default()
            }),
        )
    }

    fn host(ip: &str, mac: &str, ports: Vec<PortResult>) -> HostReport {
        let mut h = HostReport::new(ip.parse().unwrap(), None, HostState::Up);
        h.mac = Some(mac.parse().unwrap());
        h.ports = ports;
        h
    }

    /// A gateway-hosted decoy: ten unrelated ports, all silent, sharing
    /// the gateway's MAC.
    #[test]
    fn decoy_with_shared_mac_is_tagged() {
        let decoy_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389]
            .map(silent)
            .to_vec();
        let mut hosts = vec![
            host("10.9.0.1", "02:00:5e:10:20:30", vec![]),
            host("10.9.0.2", "02:00:5e:10:20:30", decoy_ports),
            host("10.9.0.3", "02:00:5e:aa:bb:cc", vec![]),
        ];
        tag_hosts(&mut hosts);
        assert_eq!(hosts[1].tags, [LIKELY_HONEYPOT]);
        assert_eq!(
            hosts[1].tag_reasons,
            [
                "10 ports accept connections but send nothing",
                "same MAC as 10.9.0.1"
            ]
        );
        assert!(hosts[0].tags.is_empty() && hosts[2].tags.is_empty());

        let json = serde_json::to_string(&hosts[1]).unwrap();
        assert!(
            json.contains(r#""tags":["likely_honeypot_or_tarpit"]"#),
            "{json}"
        );
        let plain = serde_json::to_string(&hosts[0]).unwrap();
        assert!(!plain.contains("tags"), "empty tags are left out: {plain}");
    }

    #[test]
    fn real_hosts_are_not_tagged() {
        let ip: IpAddr = "10.9.0.5".parse().unwrap();
        // One identified service is enough to clear the host.
        let mut ports = [21, 23, 25, 80, 110].map(silent).to_vec();
        assert!(!honeypot_reasons(ip, &ports, None, []).is_empty());
        ports.push(port(
            22,
            Some(Service {
                name: "ssh".into(),
                method: DetectMethod::Banner,
                ..Default::default()
            }),
        ));
        assert!(honeypot_reasons(ip, &ports, None, []).is_empty());

        // Client-speaks-first and print ports don't count towards five.
        let windows = [53, 88, 135, 389, 9100, 21, 80].map(silent).to_vec();
        assert!(honeypot_reasons(ip, &windows, None, []).is_empty());
        let few = [21, 23, 25, 80].map(silent).to_vec();
        assert!(honeypot_reasons(ip, &few, None, []).is_empty());
    }

    #[test]
    fn hosts_saved_before_tags_still_load() {
        let old = r#"{"ip":"10.9.0.7","state":"up","ports":[]}"#;
        let h: HostReport = serde_json::from_str(old).unwrap();
        assert!(h.tags.is_empty() && h.tag_reasons.is_empty());
    }

    #[test]
    fn banner_less_ports_count_as_quiet() {
        let ip: IpAddr = "10.9.0.6".parse().unwrap();
        let ports: Vec<PortResult> = [21, 23, 25, 80, 110]
            .into_iter()
            .map(|p| port(p, None))
            .collect();
        assert_eq!(honeypot_reasons(ip, &ports, None, []).len(), 1);
    }
}
