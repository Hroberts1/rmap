//! Recognising one device behind several addresses: a server wired and on
//! Wi-Fi, a NAS with two NICs, a decoy address answering with the gateway's
//! MAC. Pure: derived from the hosts alone, so it can be recomputed any time.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use rmap_core::MacAddr;
use serde::{Deserialize, Serialize};

use crate::model::{HostReport, ScanReport};

/// A fingerprint on more hosts than this is a shared default (a vendor's
/// stock certificate, a cloned VM image's host key), not one device.
pub const MAX_SHARED_FINGERPRINT: usize = 4;

/// The addresses rmap believes belong to one device, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroup {
    /// 1-based, in order of each group's lowest address.
    pub id: usize,
    /// Every address of the device, lowest first. The first is shown as the
    /// device's main row.
    pub members: Vec<IpAddr>,
    /// One per link that joined two addresses: `10.0.0.2 = 10.0.0.3: same MAC`.
    pub reasons: Vec<String>,
}

/// Each up host's device group, keyed by address. Hosts alone on their
/// device aren't in the map.
pub fn device_groups<'a>(
    hosts: impl IntoIterator<Item = &'a HostReport>,
) -> BTreeMap<IpAddr, DeviceGroup> {
    correlate(hosts).0
}

/// Fill each host's `device_group` and the report's `devices` count, and
/// log fingerprints ignored as shared defaults.
pub fn assign(r: &mut ScanReport) {
    let (groups, ignored) = correlate(&r.hosts);
    for (fp, n) in ignored {
        rmap_log::info!("not grouping by {fp}: shared by {n} hosts, likely a vendor default");
    }
    // Each group of n addresses is n - 1 fewer devices than hosts up.
    let merged = groups
        .iter()
        .filter(|(ip, g)| g.members.first() == Some(ip))
        .map(|(_, g)| g.members.len() - 1)
        .sum::<usize>();
    r.devices = Some(r.hosts_up().saturating_sub(merged));
    for h in &mut r.hosts {
        h.device_group = groups.get(&h.ip).cloned();
    }
}

/// Merge `items` (already in display order) that are the same finding on
/// one device. `key` gives an item's address and what makes it the same
/// finding (e.g. CVE id and product version). The first of each set is
/// kept, with every address it was seen on.
pub fn dedup_per_device<T>(
    items: Vec<T>,
    groups: &BTreeMap<IpAddr, DeviceGroup>,
    key: impl Fn(&T) -> (IpAddr, String),
) -> Vec<(T, Vec<IpAddr>)> {
    let mut out: Vec<(T, Vec<IpAddr>)> = Vec::new();
    let mut seen: HashMap<(Result<usize, IpAddr>, String), usize> = HashMap::new();
    for item in items {
        let (ip, what) = key(&item);
        let device = groups.get(&ip).map_or(Err(ip), |g| Ok(g.id));
        match seen.get(&(device, what.clone())) {
            Some(&i) => {
                if !out[i].1.contains(&ip) {
                    out[i].1.push(ip);
                }
            }
            None => {
                seen.insert((device, what), out.len());
                out.push((item, vec![ip]));
            }
        }
    }
    out
}

/// Unicast and not all zeros: a MAC that names one interface.
fn usable(m: MacAddr) -> bool {
    m.0 != [0; 6] && m.0[0] & 1 == 0
}

fn short_names(h: &HostReport) -> Vec<String> {
    h.hostname
        .iter()
        .chain(h.names.iter().map(|n| &n.name))
        .filter_map(|n| n.split('.').next())
        .filter(|n| !n.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn fingerprint_reason(fp: &str) -> &'static str {
    if fp.starts_with("ssh-") {
        "same SSH host key"
    } else if fp.starts_with("tls-cert ") {
        "same TLS certificate"
    } else {
        "same fingerprint"
    }
}

struct UnionFind(Vec<usize>);

impl UnionFind {
    fn find(&mut self, mut i: usize) -> usize {
        while self.0[i] != i {
            self.0[i] = self.0[self.0[i]];
            i = self.0[i];
        }
        i
    }

    /// Joins the sets of `a` and `b`; false if already joined.
    fn union(&mut self, a: usize, b: usize) -> bool {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return false;
        }
        self.0[a.max(b)] = a.min(b);
        true
    }
}

type Ignored = Vec<(String, usize)>;

fn correlate<'a>(
    hosts: impl IntoIterator<Item = &'a HostReport>,
) -> (BTreeMap<IpAddr, DeviceGroup>, Ignored) {
    let mut up: Vec<&HostReport> = hosts.into_iter().filter(|h| h.is_up()).collect();
    up.sort_by_key(|h| h.ip);
    up.dedup_by_key(|h| h.ip);
    let mut sets = UnionFind((0..up.len()).collect());
    let mut links: Vec<(usize, String)> = Vec::new();
    let mut link = |a: usize, b: usize, why: &str| {
        if sets.union(a, b) {
            links.push((a, format!("{} = {}: {why}", up[a].ip, up[b].ip)));
        }
    };

    // Strongest first, so each address's recorded reason is the best one.
    let mut by_mac: HashMap<MacAddr, usize> = HashMap::new();
    for (i, h) in up.iter().enumerate() {
        if let Some(m) = h.mac.filter(|m| usable(*m)) {
            match by_mac.get(&m) {
                Some(&first) => link(first, i, "same MAC"),
                None => {
                    by_mac.insert(m, i);
                }
            }
        }
    }

    let mut by_fp: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, h) in up.iter().enumerate() {
        let fps = h.ports.iter().filter_map(|p| p.service.as_ref());
        for fp in fps.flat_map(|s| &s.fingerprints) {
            let seen = by_fp.entry(fp).or_default();
            if seen.last() != Some(&i) {
                seen.push(i);
            }
        }
    }
    let mut ignored = Vec::new();
    for (fp, hosts) in &by_fp {
        if hosts.len() > MAX_SHARED_FINGERPRINT {
            ignored.push((fp.to_string(), hosts.len()));
            continue;
        }
        for &other in &hosts[1..] {
            link(hosts[0], other, fingerprint_reason(fp));
        }
    }

    // Adjacent burned-in MACs (a multi-port NIC) need a second signal: two
    // machines from one batch can have neighbouring addresses too.
    let mut burned: Vec<(u64, usize)> = up
        .iter()
        .enumerate()
        .filter_map(|(i, h)| h.mac.map(|m| (m, i)))
        .filter(|(m, _)| usable(*m) && !m.is_locally_administered())
        .map(|(m, i)| (m.0.iter().fold(0u64, |n, b| n << 8 | u64::from(*b)), i))
        .collect();
    burned.sort_unstable();
    for (x, &(ma, a)) in burned.iter().enumerate() {
        for &(mb, b) in &burned[x + 1..] {
            // Same OUI and the NIC part 1-2 apart.
            if mb - ma > 2 || mb >> 24 != ma >> 24 {
                break;
            }
            if mb == ma {
                continue;
            }
            let (ha, hb) = (up[a], up[b]);
            let names = short_names(hb);
            if short_names(ha).iter().any(|n| names.contains(n)) {
                link(a, b, "adjacent MACs, same name");
            } else if ha.vendor.is_some() && ha.vendor == hb.vendor {
                link(a, b, "adjacent MACs, same vendor");
            }
        }
    }

    let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..up.len() {
        members.entry(sets.find(i)).or_default().push(i);
    }
    let mut reasons: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for (a, why) in links {
        reasons.entry(sets.find(a)).or_default().push(why);
    }
    // Roots are each set's lowest index, i.e. lowest address, so this
    // iterates groups in address order.
    let mut out = BTreeMap::new();
    for (id, (root, idx)) in members.into_iter().filter(|(_, m)| m.len() > 1).enumerate() {
        let group = DeviceGroup {
            id: id + 1,
            members: idx.iter().map(|&i| up[i].ip).collect(),
            reasons: reasons.remove(&root).unwrap_or_default(),
        };
        for ip in &group.members {
            out.insert(*ip, group.clone());
        }
    }
    (out, ignored)
}

#[cfg(test)]
mod tests {
    use rmap_core::{HostState, PortResult, PortState, Protocol, Service};

    use super::*;
    use crate::builder::tests::ip;

    fn host(addr: &str, mac: Option<[u8; 6]>) -> HostReport {
        let mut h = HostReport::new(ip(addr), None, HostState::Up);
        h.mac = mac.map(MacAddr);
        h
    }

    fn with_fp(mut h: HostReport, fp: &str) -> HostReport {
        let mut p = PortResult::new(22, Protocol::Tcp, PortState::Open, None);
        p.service = Some(Service {
            name: "ssh".into(),
            fingerprints: vec![fp.into()],
            ..Default::default()
        });
        h.ports.push(p);
        h
    }

    const A: [u8; 6] = [0x00, 0x11, 0x32, 0x00, 0x00, 0x10];
    const A1: [u8; 6] = [0x00, 0x11, 0x32, 0x00, 0x00, 0x11];
    const B: [u8; 6] = [0x00, 0x50, 0x56, 0x00, 0x00, 0x20];

    fn members(g: &BTreeMap<IpAddr, DeviceGroup>, addr: &str) -> Vec<String> {
        g.get(&ip(addr)).map_or(vec![], |g| {
            g.members.iter().map(|m| m.to_string()).collect()
        })
    }

    #[test]
    fn same_mac_is_one_device() {
        let hosts = [
            host("10.0.0.20", Some(A)),
            host("10.0.0.88", Some(A)),
            host("10.0.0.5", Some(B)),
        ];
        let g = device_groups(&hosts);
        assert_eq!(members(&g, "10.0.0.88"), ["10.0.0.20", "10.0.0.88"]);
        assert_eq!(
            g[&ip("10.0.0.20")].reasons,
            ["10.0.0.20 = 10.0.0.88: same MAC"]
        );
        assert_eq!(g[&ip("10.0.0.20")].id, 1);
        assert!(!g.contains_key(&ip("10.0.0.5")));
    }

    #[test]
    fn down_hosts_and_junk_macs_never_group() {
        let mut down = host("10.0.0.2", Some(A));
        down.state = HostState::Down;
        let zero = [0; 6];
        let bcast = [0xff; 6];
        let hosts = [
            down,
            host("10.0.0.3", Some(A)),
            host("10.0.0.4", Some(zero)),
            host("10.0.0.5", Some(zero)),
            host("10.0.0.6", Some(bcast)),
            host("10.0.0.7", Some(bcast)),
        ];
        assert!(device_groups(&hosts).is_empty());
    }

    #[test]
    fn adjacent_macs_need_a_second_signal() {
        let mut a = host("10.0.0.146", Some(A));
        let mut b = host("10.0.0.147", Some(A1));
        assert!(device_groups([&a, &b]).is_empty(), "adjacent MACs alone");

        a.hostname = Some("NAS01.corp.example".into());
        b.hostname = Some("nas01".into());
        let g = device_groups([&a, &b]);
        assert_eq!(members(&g, "10.0.0.146"), ["10.0.0.146", "10.0.0.147"]);
        assert!(g[&ip("10.0.0.146")].reasons[0].ends_with("adjacent MACs, same name"));

        b.hostname = Some("other".into());
        a.vendor = Some("Synology".into());
        b.vendor = Some("Synology".into());
        let g = device_groups([&a, &b]);
        assert!(g[&ip("10.0.0.147")].reasons[0].ends_with("same vendor"));

        // Three apart, or a different OUI, isn't adjacent.
        b.mac = Some(MacAddr([0x00, 0x11, 0x32, 0x00, 0x00, 0x13]));
        assert!(device_groups([&a, &b]).is_empty());
        b.mac = Some(MacAddr([0x00, 0x11, 0x33, 0x00, 0x00, 0x10]));
        assert!(device_groups([&a, &b]).is_empty());
    }

    #[test]
    fn shared_fingerprint_groups_unless_widely_shared() {
        let key = "ssh-ed25519 SHA256:abc";
        let hosts = [
            with_fp(host("10.0.0.20", None), key),
            with_fp(host("10.0.0.88", None), key),
        ];
        let g = device_groups(&hosts);
        assert_eq!(members(&g, "10.0.0.20"), ["10.0.0.20", "10.0.0.88"]);
        assert!(g[&ip("10.0.0.20")].reasons[0].ends_with("same SSH host key"));

        let cert = "tls-cert SHA256:00ff";
        let fleet: Vec<_> = (1..=10)
            .map(|n| with_fp(host(&format!("10.0.1.{n}"), None), cert))
            .collect();
        let (g, ignored) = correlate(&fleet);
        assert!(g.is_empty());
        assert_eq!(ignored, [(cert.to_string(), 10)]);
    }

    #[test]
    fn groups_are_transitive() {
        let fp = "tls-cert SHA256:aa";
        let hosts = [
            host("10.0.0.1", Some(A)),
            with_fp(host("10.0.0.2", Some(A)), fp),
            with_fp(host("10.0.0.3", Some(B)), fp),
            host("10.0.0.9", None),
        ];
        let g = device_groups(&hosts);
        assert_eq!(
            members(&g, "10.0.0.3"),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        );
        assert_eq!(
            g[&ip("10.0.0.1")].reasons,
            [
                "10.0.0.1 = 10.0.0.2: same MAC",
                "10.0.0.2 = 10.0.0.3: same TLS certificate"
            ]
        );
    }

    #[test]
    fn dedup_merges_only_within_a_device() {
        let hosts = [
            host("10.0.0.1", Some(A)),
            host("10.0.0.2", Some(A)),
            host("10.0.0.3", None),
        ];
        let g = device_groups(&hosts);
        let items = vec![
            ("10.0.0.1", "CVE-1"),
            ("10.0.0.2", "CVE-1"),
            ("10.0.0.3", "CVE-1"),
            ("10.0.0.2", "CVE-2"),
        ];
        let out = dedup_per_device(items, &g, |(a, id)| (ip(a), id.to_string()));
        let flat: Vec<_> = out.iter().map(|(i, ips)| (i.1, ips.len())).collect();
        assert_eq!(flat, [("CVE-1", 2), ("CVE-1", 1), ("CVE-2", 1)]);
    }
}
