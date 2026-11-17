//! Edge cases and randomised robustness tests for user-input parsing.
//!
//! Every string a user can type reaches these parsers, so they must reject
//! bad input with an error and never panic.

use std::net::IpAddr;

use rmap_core::target::MAX_HOSTS_PER_TARGET;
use rmap_core::{PortList, Target, Timing, parse_targets};

fn one(s: &str) -> Target {
    let mut t = parse_targets(s).unwrap_or_else(|e| panic!("{s:?} should parse: {e}"));
    assert_eq!(t.len(), 1, "{s:?}");
    t.remove(0)
}

fn addrs(t: &Target) -> Vec<IpAddr> {
    t.addrs().collect()
}

// ------------------------------------------------------------- targets ---

#[test]
fn separators_and_stray_commas() {
    let t = parse_targets(" 10.0.0.1,,10.0.0.2\t10.0.0.3\n10.0.0.4 , ").unwrap();
    assert_eq!(t.len(), 4);
    for bad in ["", "   ", ",", " , ,\n"] {
        assert!(parse_targets(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn top_of_ipv4_space_does_not_overflow() {
    assert_eq!(addrs(&one("255.255.255.254-255.255.255.255")).len(), 2);
    assert_eq!(addrs(&one("255.255.255.255/32")).len(), 1);
    assert_eq!(
        addrs(&one("255.255.255.252/30"))
            .last()
            .unwrap()
            .to_string(),
        "255.255.255.255"
    );
    assert_eq!(addrs(&one("0.0.0.0/30"))[0].to_string(), "0.0.0.0");
}

#[test]
fn size_limits() {
    assert_eq!(one("10.0.0.0/8").count(), MAX_HOSTS_PER_TARGET);
    assert!(parse_targets("0.0.0.0/0").is_err());
    assert!(parse_targets("10.0.0.0/7").is_err());
    assert!(parse_targets("0-255.0-255.0-255.0-255").is_err());
    assert_eq!(one("10.0-255.0-255.0-255").count(), MAX_HOSTS_PER_TARGET);
    assert!(parse_targets("0.0.0.0-255.255.255.255").is_err());
}

#[test]
fn malformed_cidr() {
    for bad in [
        "10.0.0.0/",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "10.0.0.0/abc",
        "/24",
        "host.lan/24",
        "::/129",
        "10.0.0.0/24/1",
    ] {
        assert!(parse_targets(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn malformed_ranges_and_octets() {
    for bad in [
        "10.0.0.1-",
        "-10.0.0.1",
        "10.0.0.1--5",
        "10.0.0",
        "10.0.0.0.0",
        "10..0.1",
        "10.0.0.1-2-3",
        "10.0.0.300-301",
        "1.2.3.4-1.2.3",
        "10.0.0.5-10.0.0.4",
    ] {
        assert!(parse_targets(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn ipv6_forms() {
    assert_eq!(one("::1").count(), 1);
    assert_eq!(one("2001:db8::/120").count(), 256);
    assert_eq!(one("2001:db8::1-2001:db8::4").count(), 4);
    assert!(parse_targets("2001:db8::4-2001:db8::1").is_err());
    assert!(
        parse_targets("2001:db8::-2001:db8::1:0").is_err(),
        "over 65,536 addresses"
    );
    assert!(parse_targets("2001:db8::/64").is_err());
    assert!(
        parse_targets("fe80::1%eth0").is_err(),
        "zone IDs aren't supported yet"
    );
}

#[test]
fn hostname_boundaries() {
    let label63 = "a".repeat(63);
    assert!(matches!(
        one(&format!("{label63}.com")),
        Target::Hostname(_)
    ));
    assert!(
        parse_targets(&format!("{}a.com", label63)).is_err(),
        "64-char label"
    );
    let long = vec!["abcdefghi"; 25].join("."); // 249 chars
    assert!(matches!(one(&long), Target::Hostname(_)));
    let too_long = vec!["abcdefghi"; 26].join("."); // 259 chars
    assert!(parse_targets(&too_long).is_err());
    assert!(
        matches!(one("example.com."), Target::Hostname(_)),
        "FQDN trailing dot"
    );
    for bad in [
        "a..b",
        ".a",
        "a-.com",
        "under_score.com",
        "émoji.com",
        "a.b..",
        "1.2.3",
        "host.123",
    ] {
        assert!(parse_targets(bad).is_err(), "{bad:?}");
    }
    assert!(
        matches!(one("123.example"), Target::Hostname(_)),
        "numeric labels are fine before the TLD"
    );
    assert_eq!(
        parse_targets("ex ample").unwrap().len(),
        2,
        "whitespace separates targets"
    );
}

#[test]
fn display_round_trips() {
    for s in [
        "10.0.0.1",
        "10.0.0.0/30",
        "10.0.0.5-10.0.1.2",
        "192.168.1-2.10-20",
        "::1",
        "2001:db8::/126",
        "2001:db8::1-2001:db8::9",
        "router.lan",
    ] {
        let t = one(s);
        let again = one(&t.to_string());
        assert_eq!(t.count(), again.count(), "{s} -> {t}");
        assert_eq!(addrs(&t), addrs(&again), "{s} -> {t}");
    }
}

#[test]
fn counts_match_iteration() {
    for s in [
        "10.0.0.0/24",
        "10.0.1-3.0-9",
        "2001:db8::/116",
        "172.16.0.250-172.16.1.5",
    ] {
        let t = one(s);
        assert_eq!(t.count(), addrs(&t).len() as u64, "{s}");
    }
}

// --------------------------------------------------------------- ports ---

#[test]
fn port_edges() {
    assert_eq!(PortList::parse("65535").unwrap().as_slice(), &[65535]);
    assert_eq!(PortList::parse("1-65535").unwrap().len(), 65535);
    assert_eq!(PortList::parse("all,22,COMMON").unwrap().len(), 65535);
    assert_eq!(PortList::parse(" 22 , 80 ").unwrap().as_slice(), &[22, 80]);
    assert_eq!(PortList::parse("22-22").unwrap().as_slice(), &[22]);
    for bad in [
        "-22", "22-", "1-65536", "0", "a-b", "22.5", "--", "1-2-3", "+22",
    ] {
        assert!(PortList::parse(bad).is_err(), "{bad:?}");
    }
}

// -------------------------------------------------------------- timing ---

#[test]
fn timing_templates_get_faster() {
    let all: Vec<Timing> = (0..=5).map(Timing::template).collect();
    for w in all.windows(2) {
        assert!(
            w[0].concurrency <= w[1].concurrency,
            "{} -> {}",
            w[0].name,
            w[1].name
        );
        assert!(
            w[0].connect_timeout >= w[1].connect_timeout,
            "{} -> {}",
            w[0].name,
            w[1].name
        );
        assert!(
            w[0].scan_delay >= w[1].scan_delay,
            "{} -> {}",
            w[0].name,
            w[1].name
        );
    }
    assert!(
        all.iter()
            .all(|t| t.concurrency < 1024 && t.concurrency >= 1 && t.host_parallelism >= 1)
    );
    assert_eq!(Timing::template(200), Timing::template(5));
    assert_eq!(Timing::default().name, "normal");
}

// ---------------------------------------------------------- randomised ---

/// Small deterministic PRNG so failures reproduce from the printed seed.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next() % items.len() as u64) as usize]
    }
}

/// Fragments likely to hit parser edge cases when glued together.
const PIECES: &[&str] = &[
    "0",
    "1",
    "9",
    "10",
    "25",
    "255",
    "256",
    "999",
    "65535",
    "65536",
    "4294967296",
    ".",
    "..",
    "/",
    "-",
    ",",
    " ",
    ":",
    "::",
    "a",
    "f",
    "ff",
    "z",
    "_",
    "%",
    "*",
    "all",
    "common",
    "localhost",
    "/0",
    "/8",
    "/24",
    "/32",
    "/33",
    "/112",
    "/128",
    "é",
    "\u{0}",
    "\n",
];

fn random_input(rng: &mut XorShift) -> String {
    let len = (rng.next() % 12) as usize;
    (0..len).map(|_| rng.pick(PIECES)).collect()
}

#[test]
fn random_target_strings_never_panic() {
    let seed = 0x5eed_0f7a_96e7;
    let mut rng = XorShift(seed);
    for i in 0..50_000 {
        let input = random_input(&mut rng);
        let result = std::panic::catch_unwind(|| {
            if let Ok(targets) = parse_targets(&input) {
                for t in &targets {
                    let n = t.count();
                    assert!((1..=MAX_HOSTS_PER_TARGET).contains(&n));
                    let first: Vec<IpAddr> = t.addrs().take(3).collect();
                    assert!(matches!(t, Target::Hostname(_)) || !first.is_empty());
                    let _ = t.may_be_public();
                    let _ = t.to_string();
                }
            }
        });
        assert!(
            result.is_ok(),
            "seed {seed:#x} iteration {i}: input {input:?} panicked"
        );
    }
}

#[test]
fn random_port_strings_never_panic() {
    let seed = 0xb0a7_5eed;
    let mut rng = XorShift(seed);
    for i in 0..50_000 {
        let input = random_input(&mut rng);
        let result = std::panic::catch_unwind(|| {
            if let Ok(ports) = PortList::parse(&input) {
                let p = ports.as_slice();
                assert!(!p.is_empty() && p[0] >= 1);
                assert!(p.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
            }
        });
        assert!(
            result.is_ok(),
            "seed {seed:#x} iteration {i}: input {input:?} panicked"
        );
    }
}
