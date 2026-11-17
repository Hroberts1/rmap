//! Engine tests against real sockets on the loopback interface and the
//! reserved TEST-NET-1 block (192.0.2.0/24), which is never routed.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rmap_core::{PortList, Target, Timing, parse_targets};
use tokio::net::TcpListener;
use tokio::time::timeout;

use super::*;

/// Hosts with this address panic in `scan_host`, to test failure handling.
pub const PANIC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 66));

/// Generous timeouts: Windows waits about 2s before reporting a refused
/// connection on loopback, and slow CI machines need headroom.
fn patient() -> Timing {
    Timing {
        connect_timeout: Duration::from_secs(5),
        retries: 0,
        ..Timing::template(4)
    }
}

fn config(targets: &str, ports: &str, timing: Timing, discovery: bool) -> ScanConfig {
    ScanConfig {
        targets: parse_targets(targets).unwrap(),
        ports: PortList::parse(ports).unwrap(),
        timing,
        discovery,
    }
}

async fn listener() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let _ = l.accept().await;
        }
    });
    port
}

/// A port that was just released, so nothing is listening on it.
async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

struct Outcome {
    events: Vec<ScanEvent>,
    scan: Scan,
}

impl Outcome {
    fn open_ports(&self) -> Vec<(IpAddr, u16)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Port { ip, result } => Some((*ip, result.port)),
                _ => None,
            })
            .collect()
    }

    fn host_done(&self) -> Vec<(IpAddr, u32, u32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::HostDone {
                    ip,
                    closed,
                    filtered,
                    ..
                } => Some((*ip, *closed, *filtered)),
                _ => None,
            })
            .collect()
    }

    fn hosts(&self) -> Vec<(IpAddr, Option<String>, HostState)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Host {
                    ip,
                    hostname,
                    state,
                    ..
                } => Some((*ip, hostname.clone(), *state)),
                _ => None,
            })
            .collect()
    }

    fn warnings(&self) -> Vec<&str> {
        self.events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Warning(w) => Some(w.as_str()),
                _ => None,
            })
            .collect()
    }

    fn finished(&self) -> bool {
        matches!(self.events.last(), Some(ScanEvent::Finished { .. }))
    }
}

/// Run a scan to completion, failing the test if it takes over 30 seconds.
async fn run_scan(config: ScanConfig) -> Outcome {
    let mut scan = Scan::start(&Handle::current(), config);
    let mut events = Vec::new();
    let collect = async {
        while let Some(ev) = scan.events.recv().await {
            let done = matches!(ev, ScanEvent::Finished { .. });
            events.push(ev);
            if done {
                break;
            }
        }
    };
    timeout(Duration::from_secs(30), collect)
        .await
        .expect("scan did not finish in 30s");
    Outcome { events, scan }
}

#[tokio::test(flavor = "multi_thread")]
async fn finds_an_open_port() {
    let port = listener().await;
    let out = run_scan(config("127.0.0.1", &port.to_string(), patient(), false)).await;
    assert_eq!(out.open_ports(), [("127.0.0.1".parse().unwrap(), port)]);
    assert!(out.finished());
    assert_eq!(out.scan.progress.ratio(), 1.0);
    assert!(matches!(
        out.events[0],
        ScanEvent::Started {
            hosts: 1,
            ports_per_host: 1
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_a_closed_port() {
    let port = closed_port().await;
    let out = run_scan(config("127.0.0.1", &port.to_string(), patient(), false)).await;
    assert!(out.open_ports().is_empty());
    assert_eq!(out.host_done(), [("127.0.0.1".parse().unwrap(), 1, 0)]);
    assert_eq!(out.scan.stats.closed.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn unroutable_port_is_filtered() {
    let timing = Timing {
        connect_timeout: Duration::from_millis(200),
        retries: 1,
        ..Timing::template(4)
    };
    let out = run_scan(config("192.0.2.1", "80", timing, false)).await;
    assert_eq!(out.host_done(), [("192.0.2.1".parse().unwrap(), 0, 1)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_ports_add_up() {
    let open_a = listener().await;
    let open_b = listener().await;
    let shut = closed_port().await;
    let ports = format!("{open_a},{open_b},{shut}");
    let out = run_scan(config("127.0.0.1", &ports, patient(), false)).await;

    let mut open: Vec<u16> = out.open_ports().iter().map(|(_, p)| *p).collect();
    open.sort();
    let mut expected = vec![open_a, open_b];
    expected.sort();
    assert_eq!(open, expected);
    assert_eq!(out.host_done()[0].1, 1);

    let s = &out.scan.stats;
    let total = s.open.load(Ordering::Relaxed)
        + s.closed.load(Ordering::Relaxed)
        + s.filtered.load(Ordering::Relaxed);
    assert_eq!(total, 3);
    assert_eq!(out.scan.progress.completed.load(Ordering::Relaxed), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn scans_several_hosts() {
    // All of 127.0.0.0/8 is loopback, but the listener is only on .1.
    let port = listener().await;
    let out = run_scan(config("127.0.0.1-4", &port.to_string(), patient(), false)).await;
    assert_eq!(out.host_done().len(), 4);
    assert_eq!(out.open_ports(), [("127.0.0.1".parse().unwrap(), port)]);
    assert_eq!(out.scan.stats.hosts_up.load(Ordering::Relaxed), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_skips_dead_hosts() {
    let timing = Timing {
        connect_timeout: Duration::from_millis(300),
        retries: 0,
        ..Timing::template(4)
    };
    let out = run_scan(config("192.0.2.1", "1-100", timing, true)).await;
    assert_eq!(
        out.hosts(),
        [("192.0.2.1".parse().unwrap(), None, HostState::Down)]
    );
    assert!(
        out.host_done().is_empty(),
        "down hosts are not port scanned"
    );
    assert_eq!(
        out.scan.progress.ratio(),
        1.0,
        "skipped ports still count toward progress"
    );
    assert_eq!(out.scan.stats.hosts_down.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_finds_loopback_up() {
    // Loopback answers on every discovery port, with a refusal if nothing listens.
    let port = listener().await;
    let out = run_scan(config("127.0.0.1", &port.to_string(), patient(), true)).await;
    assert_eq!(out.hosts()[0].2, HostState::Up);
    assert_eq!(out.open_ports().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn resolves_hostnames() {
    let port = listener().await;
    let out = run_scan(config("localhost", &port.to_string(), patient(), false)).await;
    let hosts = out.hosts();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].1.as_deref(), Some("localhost"));
    assert!(hosts[0].0.is_loopback());
}

#[tokio::test(flavor = "multi_thread")]
async fn unresolvable_hostname_warns_and_finishes() {
    // .invalid is reserved and guaranteed never to resolve.
    let out = run_scan(config("no-such-host.invalid", "80,443", patient(), false)).await;
    assert!(out.finished());
    assert!(out.hosts().is_empty());
    assert!(
        out.warnings()
            .iter()
            .any(|w| w.contains("could not resolve no-such-host.invalid"))
    );
    assert_eq!(out.scan.progress.ratio(), 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_cancels_promptly() {
    let timing = Timing {
        connect_timeout: Duration::from_secs(10),
        retries: 3,
        ..Timing::template(3)
    };
    let mut scan = Scan::start(
        &Handle::current(),
        config("192.0.2.0/28", "1-1000", timing, false),
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    scan.stop();
    let drained = timeout(Duration::from_secs(5), async {
        let mut finished = false;
        while let Some(ev) = scan.events.recv().await {
            finished |= matches!(ev, ScanEvent::Finished { .. });
        }
        finished
    })
    .await
    .expect("channel should close soon after stop");
    assert!(!drained, "a stopped scan never reports Finished");
    assert!(scan.is_finished());
    assert!(scan.progress.ratio() < 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn host_panic_is_contained() {
    let port = listener().await;
    let targets = format!("{PANIC_IP},127.0.0.1");
    let out = run_scan(config(&targets, &port.to_string(), patient(), false)).await;
    assert!(out.finished(), "the scan survives a panicking host task");
    assert_eq!(out.open_ports().len(), 1, "other hosts still get scanned");
    assert!(out.warnings().iter().any(|w| w.contains("internal error")));
    assert_eq!(out.scan.stats.task_panics.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrency_of_one_still_completes() {
    let port = listener().await;
    let shut = closed_port().await;
    let timing = Timing {
        concurrency: 1,
        host_parallelism: 1,
        ..patient()
    };
    let out = run_scan(config(
        "127.0.0.1",
        &format!("{port},{shut}"),
        timing,
        false,
    ))
    .await;
    assert_eq!(out.open_ports().len(), 1);
    assert_eq!(out.scan.progress.completed.load(Ordering::Relaxed), 2);
}

#[test]
fn error_tally_orders_by_frequency() {
    let stats = Stats::default();
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    for _ in 0..3 {
        stats.record_error(ip, 80, &io::ErrorKind::HostUnreachable.into());
    }
    stats.record_error(ip, 80, &io::ErrorKind::PermissionDenied.into());
    assert_eq!(
        stats.error_summary(),
        "HostUnreachable=3 PermissionDenied=1"
    );
    assert_eq!(stats.unexpected_errors.load(Ordering::Relaxed), 4);
}

#[test]
fn describe_truncates_long_target_lists() {
    let targets: Vec<String> = (1..=15).map(|i| format!("10.0.0.{i}")).collect();
    let c = config(&targets.join(","), "22", Timing::default(), true);
    let d = c.describe();
    assert!(d.contains("10.0.0.10,+5 more"), "{d}");
    assert!(
        d.contains("timing=T3(normal)") && d.contains("discovery=true"),
        "{d}"
    );
    assert!(!d.contains("10.0.0.11"));
}

#[test]
fn hostname_target_counts_as_one_host() {
    assert_eq!(Target::Hostname("x".into()).count(), 1);
}
