//! Target specification parsing.
//!
//! Accepted forms, separated by commas or whitespace:
//! - single addresses: `192.168.1.10`, `::1`
//! - CIDR blocks: `10.0.0.0/24`, `fe80::/120`
//! - full IPv4 ranges: `10.0.0.5-10.0.0.40`
//! - per-octet ranges: `192.168.1-3.1-254`, `10.0.0.1-50`
//! - hostnames: `router.lan`, `example.com`

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{ParseError, err};

/// Largest number of addresses a single target may expand to (a /8).
pub const MAX_HOSTS_PER_TARGET: u64 = 1 << 24;
/// Smallest IPv6 prefix accepted (a /112 is 65,536 addresses).
const MIN_V6_PREFIX: u8 = 112;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Inclusive IPv4 range.
    V4Range { start: Ipv4Addr, end: Ipv4Addr },
    /// Nmap-style per-octet ranges, each inclusive.
    V4Octets([(u8, u8); 4]),
    /// Inclusive IPv6 range.
    V6Range { start: Ipv6Addr, end: Ipv6Addr },
    /// Name to resolve at scan time.
    Hostname(String),
}

impl Target {
    /// Number of addresses this target expands to. Hostnames count as one.
    pub fn count(&self) -> u64 {
        match self {
            Target::V4Range { start, end } => u64::from(u32::from(*end) - u32::from(*start)) + 1,
            Target::V4Octets(o) => o.iter().map(|(a, b)| u64::from(b - a) + 1).product(),
            Target::V6Range { start, end } => (u128::from(*end) - u128::from(*start)) as u64 + 1,
            Target::Hostname(_) => 1,
        }
    }

    /// Iterate over the addresses in this target. Hostnames yield nothing;
    /// they are resolved by the engine.
    pub fn addrs(&self) -> Box<dyn Iterator<Item = IpAddr> + Send> {
        match self.clone() {
            Target::V4Range { start, end } => {
                Box::new((u32::from(start)..=u32::from(end)).map(|n| IpAddr::V4(Ipv4Addr::from(n))))
            }
            Target::V4Octets(o) => Box::new((o[0].0..=o[0].1).flat_map(move |a| {
                (o[1].0..=o[1].1).flat_map(move |b| {
                    (o[2].0..=o[2].1).flat_map(move |c| {
                        (o[3].0..=o[3].1).map(move |d| IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
                    })
                })
            })),
            Target::V6Range { start, end } => Box::new(
                (u128::from(start)..=u128::from(end)).map(|n| IpAddr::V6(Ipv6Addr::from(n))),
            ),
            Target::Hostname(_) => Box::new(std::iter::empty()),
        }
    }

    /// True if any address in this target may be outside private, loopback
    /// and link-local space. Hostnames other than `localhost` count as public.
    pub fn may_be_public(&self) -> bool {
        let (lo, hi) = match self {
            Target::V4Range { start, end } => (IpAddr::V4(*start), IpAddr::V4(*end)),
            Target::V4Octets(o) => (
                IpAddr::V4(Ipv4Addr::new(o[0].0, o[1].0, o[2].0, o[3].0)),
                IpAddr::V4(Ipv4Addr::new(o[0].1, o[1].1, o[2].1, o[3].1)),
            ),
            Target::V6Range { start, end } => (IpAddr::V6(*start), IpAddr::V6(*end)),
            Target::Hostname(h) => return !h.eq_ignore_ascii_case("localhost"),
        };
        // Private blocks are prefix-aligned, so if both ends sit in the same
        // block, everything between them does too.
        match (private_block(lo), private_block(hi)) {
            (Some(a), Some(b)) => a != b,
            _ => true,
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::V4Range { start, end } if start == end => write!(f, "{start}"),
            Target::V4Range { start, end } => write!(f, "{start}-{end}"),
            Target::V4Octets(o) => {
                let parts: Vec<String> = o
                    .iter()
                    .map(|(a, b)| {
                        if a == b {
                            a.to_string()
                        } else {
                            format!("{a}-{b}")
                        }
                    })
                    .collect();
                f.write_str(&parts.join("."))
            }
            Target::V6Range { start, end } if start == end => write!(f, "{start}"),
            Target::V6Range { start, end } => write!(f, "{start}-{end}"),
            Target::Hostname(h) => f.write_str(h),
        }
    }
}

/// Identify which non-public block an address belongs to, if any.
fn private_block(ip: IpAddr) -> Option<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            match o {
                [10, ..] => Some(1),
                [172, b, ..] if (16..=31).contains(&b) => Some(2),
                [192, 168, ..] => Some(3),
                [127, ..] => Some(4),
                [169, 254, ..] => Some(5),
                [100, b, ..] if (64..=127).contains(&b) => Some(6), // CGNAT
                _ => None,
            }
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            if v6.is_loopback() {
                Some(10)
            } else if seg & 0xfe00 == 0xfc00 {
                Some(11) // unique local fc00::/7
            } else if seg & 0xffc0 == 0xfe80 {
                Some(12) // link-local fe80::/10
            } else {
                None
            }
        }
    }
}

/// Parse a full target specification into a list of targets.
pub fn parse_targets(input: &str) -> Result<Vec<Target>, ParseError> {
    let targets = input
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(parse_one)
        .collect::<Result<Vec<_>, _>>()?;
    if targets.is_empty() {
        return err("no targets given");
    }
    Ok(targets)
}

fn parse_one(s: &str) -> Result<Target, ParseError> {
    if let Some((addr, prefix)) = s.split_once('/') {
        return parse_cidr(s, addr, prefix);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(single(ip));
    }
    if let Some((a, b)) = s.split_once('-')
        && let (Ok(start), Ok(end)) = (a.parse::<Ipv4Addr>(), b.parse::<Ipv4Addr>())
    {
        if start > end {
            return err(format!("{s}: range start is after its end"));
        }
        return checked(Target::V4Range { start, end }, s);
    }
    if let Some(t) = parse_octets(s)? {
        return checked(t, s);
    }
    if is_hostname(s) {
        return Ok(Target::Hostname(s.to_ascii_lowercase()));
    }
    err(format!(
        "{s}: not an address, range, CIDR block or hostname"
    ))
}

fn single(ip: IpAddr) -> Target {
    match ip {
        IpAddr::V4(v4) => Target::V4Range { start: v4, end: v4 },
        IpAddr::V6(v6) => Target::V6Range { start: v6, end: v6 },
    }
}

fn parse_cidr(s: &str, addr: &str, prefix: &str) -> Result<Target, ParseError> {
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| ParseError(format!("{s}: CIDR base must be an IP address")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ParseError(format!("{s}: invalid prefix length")))?;
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return err(format!("{s}: IPv4 prefix must be 0-32"));
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let start = u32::from(v4) & mask;
            checked(
                Target::V4Range {
                    start: start.into(),
                    end: (start | !mask).into(),
                },
                s,
            )
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return err(format!("{s}: IPv6 prefix must be 0-128"));
            }
            if prefix < MIN_V6_PREFIX {
                return err(format!(
                    "{s}: IPv6 blocks larger than /{MIN_V6_PREFIX} are not supported"
                ));
            }
            let mask = u128::MAX << (128 - prefix);
            let start = u128::from(v6) & mask;
            Ok(Target::V6Range {
                start: start.into(),
                end: (start | !mask).into(),
            })
        }
    }
}

/// Parse `a.b.c.d` where each part is a number or an inclusive `x-y` range.
/// Returns `Ok(None)` if the string doesn't look like an octet spec at all.
fn parse_octets(s: &str) -> Result<Option<Target>, ParseError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Ok(None);
    }
    let mut octets = [(0u8, 0u8); 4];
    for (slot, part) in octets.iter_mut().zip(&parts) {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let lo: u8 = lo
            .parse()
            .map_err(|_| ParseError(format!("{s}: bad octet '{part}'")))?;
        let hi: u8 = hi
            .parse()
            .map_err(|_| ParseError(format!("{s}: bad octet '{part}'")))?;
        if lo > hi {
            return err(format!("{s}: octet range '{part}' runs backwards"));
        }
        *slot = (lo, hi);
    }
    Ok(Some(Target::V4Octets(octets)))
}

fn checked(t: Target, s: &str) -> Result<Target, ParseError> {
    if t.count() > MAX_HOSTS_PER_TARGET {
        return err(format!(
            "{s}: expands to {} hosts (limit is a /8)",
            t.count()
        ));
    }
    Ok(t)
}

fn is_hostname(s: &str) -> bool {
    s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        // An all-numeric dotted string is a malformed address, not a name.
        && !s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(s: &str) -> Vec<String> {
        parse_targets(s)
            .unwrap()
            .iter()
            .flat_map(|t| t.addrs())
            .map(|a| a.to_string())
            .collect()
    }

    #[test]
    fn single_and_list() {
        assert_eq!(
            addrs("10.0.0.1, 10.0.0.2 ::1"),
            ["10.0.0.1", "10.0.0.2", "::1"]
        );
    }

    #[test]
    fn cidr_v4() {
        let t = &parse_targets("192.168.1.77/30").unwrap()[0];
        assert_eq!(t.count(), 4);
        assert_eq!(addrs("192.168.1.77/30")[0], "192.168.1.76");
        assert_eq!(parse_targets("10.0.0.0/8").unwrap()[0].count(), 1 << 24);
        assert!(parse_targets("10.0.0.0/7").is_err());
        assert_eq!(parse_targets("1.2.3.4/32").unwrap()[0].count(), 1);
    }

    #[test]
    fn cidr_v6() {
        assert_eq!(parse_targets("fe80::/126").unwrap()[0].count(), 4);
        assert!(parse_targets("fe80::/64").is_err());
    }

    #[test]
    fn ranges() {
        assert_eq!(addrs("10.0.0.254-10.0.1.1").len(), 4);
        assert_eq!(addrs("10.0.0.1-3"), ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        assert_eq!(parse_targets("10.1-2.0.1-10").unwrap()[0].count(), 20);
        assert!(parse_targets("10.0.0.9-10.0.0.1").is_err());
        assert!(parse_targets("10.0.0.5-1").is_err());
        assert!(parse_targets("10.0.0.256").is_err());
    }

    #[test]
    fn hostnames() {
        assert_eq!(
            parse_targets("Router.LAN").unwrap()[0],
            Target::Hostname("router.lan".into())
        );
        assert!(parse_targets("bad_host!").is_err());
        assert!(parse_targets("-lead.example").is_err());
    }

    #[test]
    fn public_detection() {
        let public = |s: &str| parse_targets(s).unwrap()[0].may_be_public();
        assert!(!public("192.168.0.0/16"));
        assert!(!public("10.0.0.1-50"));
        assert!(!public("127.0.0.1"));
        assert!(!public("localhost"));
        assert!(!public("fd00::1"));
        assert!(public("8.8.8.8"));
        assert!(public("192.168.255.0-192.169.0.10"));
        assert!(public("example.com"));
    }
}
