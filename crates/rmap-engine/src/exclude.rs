//! Addresses the user asked never to probe: fragile gear such as PLCs,
//! SCADA controllers and medical devices that can fall over when scanned.
//!
//! Exclusions use the same syntax as targets. Address entries are matched
//! directly; hostname entries are resolved once at scan start to every
//! address they have (see [`resolve`]) and never match by name.

use std::io;
use std::net::IpAddr;

use rmap_core::Target;

/// True if `ip` falls inside any address entry of `exclude`.
pub fn is_excluded(exclude: &[Target], ip: IpAddr) -> bool {
    exclude.iter().any(|t| contains(t, ip))
}

fn contains(t: &Target, ip: IpAddr) -> bool {
    match (t, ip) {
        (Target::V4Range { start, end }, IpAddr::V4(a)) => (start..=end).contains(&&a),
        (Target::V4Octets(o), IpAddr::V4(a)) => a
            .octets()
            .iter()
            .zip(o)
            .all(|(x, (lo, hi))| (lo..=hi).contains(&x)),
        (Target::V6Range { start, end }, IpAddr::V6(a)) => (start..=end).contains(&&a),
        _ => false,
    }
}

/// Lowest and highest address a target can contain; `None` for hostnames.
fn bounds(t: &Target) -> Option<(IpAddr, IpAddr)> {
    match t {
        Target::V4Range { start, end } => Some(((*start).into(), (*end).into())),
        Target::V4Octets(o) => Some((
            [o[0].0, o[1].0, o[2].0, o[3].0].into(),
            [o[0].1, o[1].1, o[2].1, o[3].1].into(),
        )),
        Target::V6Range { start, end } => Some(((*start).into(), (*end).into())),
        Target::Hostname(_) => None,
    }
}

/// Hosts the scan will cover: every target address that isn't excluded.
/// Hostname targets count as one, as in [`Target::count`], since they are
/// only resolved when the scan reaches them.
pub fn count_hosts(targets: &[Target], exclude: &[Target]) -> u64 {
    targets
        .iter()
        .map(|t| {
            let Some((lo, hi)) = bounds(t) else {
                return t.count();
            };
            // Only exclusions overlapping this target can remove addresses.
            let near: Vec<Target> = exclude
                .iter()
                .filter(|e| bounds(e).is_some_and(|(elo, ehi)| elo <= hi && lo <= ehi))
                .cloned()
                .collect();
            if near.is_empty() {
                t.count()
            } else {
                // shortcut: walks every address (up to a /8, under a second
                // in debug builds); switch to interval maths if that shows.
                t.addrs().filter(|ip| !is_excluded(&near, *ip)).count() as u64
            }
        })
        .sum()
}

/// Turn hostname exclusions into the addresses they resolve to. Any name
/// that doesn't resolve is an error: an exclusion we can't place is a
/// device the scan might still hit by address.
pub(crate) async fn resolve(exclude: &[Target]) -> Result<Vec<Target>, String> {
    let mut out = Vec::with_capacity(exclude.len());
    for t in exclude {
        let Target::Hostname(name) = t else {
            out.push(t.clone());
            continue;
        };
        let addrs = lookup(name)
            .await
            .map_err(|e| format!("could not resolve excluded host {name}: {e}"))?;
        rmap_log::info!("excluded host {name} resolves to {addrs:?}");
        out.extend(addrs.into_iter().map(single));
    }
    Ok(out)
}

async fn lookup(name: &str) -> io::Result<Vec<IpAddr>> {
    let mut addrs: Vec<IpAddr> = tokio::net::lookup_host((name, 0))
        .await?
        .map(|a| a.ip())
        .collect();
    addrs.sort();
    addrs.dedup();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses returned",
        ));
    }
    Ok(addrs)
}

fn single(ip: IpAddr) -> Target {
    match ip {
        IpAddr::V4(v4) => Target::V4Range { start: v4, end: v4 },
        IpAddr::V6(v6) => Target::V6Range { start: v6, end: v6 },
    }
}

#[cfg(test)]
mod tests {
    use rmap_core::parse_targets;

    use super::*;

    fn t(s: &str) -> Vec<Target> {
        parse_targets(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn matches_every_target_form() {
        let ex = t("192.0.2.5, 192.0.2.10-192.0.2.12, 192.0.2.128/30, 192.0.2.20-21, 2001:db8::1");
        for hit in [
            "192.0.2.5",
            "192.0.2.10",
            "192.0.2.12",
            "192.0.2.131",
            "192.0.2.21",
            "2001:db8::1",
        ] {
            assert!(is_excluded(&ex, ip(hit)), "{hit}");
        }
        for miss in [
            "192.0.2.4",
            "192.0.2.13",
            "192.0.2.132",
            "192.0.2.22",
            "2001:db8::2",
            "127.0.0.1",
        ] {
            assert!(!is_excluded(&ex, ip(miss)), "{miss}");
        }
    }

    #[test]
    fn hostname_entries_never_match_by_themselves() {
        assert!(!is_excluded(&t("localhost"), ip("127.0.0.1")));
    }

    #[test]
    fn counts_skip_excluded_and_overlaps_count_once() {
        let targets = t("192.0.2.0/24");
        assert_eq!(count_hosts(&targets, &[]), 256);
        assert_eq!(count_hosts(&targets, &t("192.0.2.7")), 255);
        // .0-.15 and .8-.31 overlap; together they remove 32 addresses.
        assert_eq!(
            count_hosts(&targets, &t("192.0.2.0/28, 192.0.2.8-192.0.2.31")),
            224
        );
        // Exclusions outside the targets change nothing.
        assert_eq!(count_hosts(&targets, &t("198.51.100.0/24, ::1")), 256);
        assert_eq!(count_hosts(&targets, &t("192.0.0.0/16")), 0);
        // Overlapping targets are counted per target, as the engine scans them.
        assert_eq!(count_hosts(&t("192.0.2.1, 192.0.2.1"), &t("192.0.2.2")), 2);
        // A hostname target can't be checked until it resolves.
        assert_eq!(count_hosts(&t("router.lan"), &t("192.0.2.0/24")), 1);
    }

    #[tokio::test]
    async fn resolves_hostnames_to_addresses() {
        let ex = resolve(&t("192.0.2.9, localhost")).await.unwrap();
        assert!(is_excluded(&ex, ip("192.0.2.9")));
        assert!(ex.iter().all(|e| !matches!(e, Target::Hostname(_))));
        assert!(ex.len() >= 2);
    }

    #[tokio::test]
    async fn unresolvable_exclusion_is_an_error() {
        let e = resolve(&t("no-such-host.invalid")).await.unwrap_err();
        assert!(e.contains("no-such-host.invalid"), "{e}");
    }
}
