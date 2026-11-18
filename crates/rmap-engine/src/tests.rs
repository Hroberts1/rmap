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
        scan_type: ScanType::Connect,
        service_detection: false,
        vuln_matching: false,
        exclude: Vec::new(),
        max_rate: None,
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

// ------------------------------------------------------ SYN and UDP scans ---
//
// These run everywhere. Without raw sockets (Windows, macOS, or Linux
// without CAP_NET_RAW) the engine falls back and warns, and the results
// must be the same. The `raw_` tests below insist on the raw backend.

fn typed(targets: &str, ports: &str, timing: Timing, scan_type: ScanType) -> ScanConfig {
    ScanConfig {
        scan_type,
        ..config(targets, ports, timing, false)
    }
}

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

impl Outcome {
    fn port_states(&self) -> Vec<(u16, rmap_core::Protocol, PortState)> {
        let mut v: Vec<_> = self
            .events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Port { result, .. } => {
                    Some((result.port, result.protocol, result.state))
                }
                _ => None,
            })
            .collect();
        v.sort_by_key(|p| p.0);
        v
    }

    fn fell_back(&self) -> bool {
        self.warnings().iter().any(|w| w.contains("falling back"))
    }
}

/// A UDP service that echoes every datagram (an empty one gets a byte back).
async fn udp_echo() -> u16 {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = s.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n.max(1)], from).await;
        }
    });
    port
}

// ----------------------------------------------------- service detection ---

/// A loopback server that greets every connection with `banner` and then
/// stays silent, like an SSH daemon.
async fn banner_server(banner: &'static [u8]) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(banner).await;
                let mut buf = [0u8; 256];
                let _ = timeout(Duration::from_secs(30), s.read(&mut buf)).await;
            });
        }
    });
    port
}

/// A UDP port that is bound but never answers. Keep the socket alive.
async fn udp_silent() -> (tokio::net::UdpSocket, u16) {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = s.local_addr().unwrap().port();
    (s, port)
}

/// A UDP port nothing is bound to.
async fn udp_closed() -> u16 {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

fn udp_timing() -> Timing {
    Timing {
        connect_timeout: Duration::from_millis(1500),
        retries: 0,
        ..Timing::template(4)
    }
}

async fn check_syn_scan() -> Outcome {
    let open = listener().await;
    let shut = closed_port().await;
    let ports = format!("{open},{shut}");
    let out = run_scan(typed("127.0.0.1", &ports, patient(), ScanType::Syn)).await;
    assert!(out.finished());
    assert_eq!(out.open_ports(), [(LO, open)]);
    assert_eq!(out.host_done(), [(LO, 1, 0)], "the closed port is counted");
    assert!(
        !out.warnings().iter().any(|w| w.contains("not implemented")),
        "{:?}",
        out.warnings()
    );
    out
}

async fn check_udp_scan() -> Outcome {
    let echo = udp_echo().await;
    let (_keep, silent) = udp_silent().await;
    let shut = udp_closed().await;
    let ports = format!("{echo},{silent},{shut}");
    let out = run_scan(typed("127.0.0.1", &ports, udp_timing(), ScanType::Udp)).await;
    assert!(out.finished());
    let mut expected = vec![
        (echo, rmap_core::Protocol::Udp, PortState::Open),
        (silent, rmap_core::Protocol::Udp, PortState::OpenFiltered),
    ];
    expected.sort_by_key(|p| p.0);
    assert_eq!(out.port_states(), expected);
    assert_eq!(out.host_done(), [(LO, 1, 0)], "the unbound port is closed");
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn syn_scan_finds_open_and_closed_ports() {
    let out = check_syn_scan().await;
    if out.fell_back() {
        assert!(
            out.warnings()
                .iter()
                .any(|w| w.starts_with("SYN scan") && w.contains("TCP connect"))
        );
    }
    #[cfg(not(target_os = "linux"))]
    assert!(out.fell_back(), "raw sockets are Linux-only");
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_scan_sorts_open_silent_and_closed() {
    let out = check_udp_scan().await;
    if out.fell_back() {
        assert!(
            out.warnings()
                .iter()
                .any(|w| w.contains("unprivileged UDP"))
        );
    }
    #[cfg(not(target_os = "linux"))]
    assert!(out.fell_back(), "raw sockets are Linux-only");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_scan_never_warns_about_privileges() {
    let port = listener().await;
    let out = run_scan(config("127.0.0.1", &port.to_string(), patient(), true)).await;
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_discovery_and_unroutable_hosts_finish() {
    let timing = Timing {
        connect_timeout: Duration::from_millis(300),
        retries: 0,
        ..Timing::template(4)
    };
    let mut c = typed("192.0.2.1", "53,161", timing, ScanType::Udp);
    c.discovery = true;
    let out = run_scan(c).await;
    assert!(out.finished());
    assert_eq!(out.hosts()[0].2, HostState::Down);
}

// --------------------------------------------- raw sockets (privileged) ---
//
// These need CAP_NET_RAW, so they are ignored by default. On Linux, run
// them as root, or unprivileged inside a fresh user and network namespace,
// which grants CAP_NET_RAW over that namespace's own loopback:
//
//   cargo test -p rmap-engine --no-run
//   unshare -rn sh -c 'ip link set lo up && <test binary> --ignored raw_'

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root or CAP_NET_RAW (see comment)"]
async fn raw_syn_scan_uses_raw_sockets() {
    let out = check_syn_scan().await;
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root or CAP_NET_RAW (see comment)"]
async fn raw_udp_scan_uses_raw_sockets() {
    let out = check_udp_scan().await;
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root or CAP_NET_RAW (see comment)"]
async fn raw_syn_scan_of_many_ports() {
    let open = listener().await;
    let out = run_scan(typed("127.0.0.1", "1-2000", patient(), ScanType::Syn)).await;
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
    let found: Vec<u16> = out.open_ports().iter().map(|p| p.1).collect();
    if open <= 2000 {
        assert!(found.contains(&open));
    }
    let (_, closed, filtered) = out.host_done()[0];
    assert_eq!(found.len() as u32 + closed, 2000);
    assert_eq!(filtered, 0, "loopback answers every SYN");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root or CAP_NET_RAW (see comment)"]
async fn raw_icmp_echo_answers_on_loopback() {
    let raw = crate::raw::RawScanner::open(ScanType::Connect, &patient())
        .expect("raw sockets should open with CAP_NET_RAW");
    let rtt = raw
        .echo_ping(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, &patient())
        .await;
    assert!(rtt.is_some(), "loopback answers ICMP echo");
}

/// SYN, UDP and ARP over a real link instead of loopback. Needs a veth
/// pair into a second namespace; the test does nothing unless
/// `RMAP_VETH_PEER` names the far end. For example, inside `unshare -rn`:
///
/// ```sh
/// ip link add v0 type veth peer name v1
/// unshare -n sleep 600 & sleep 0.5; peer=$!
/// ip link set v1 netns $peer
/// nsenter -t $peer -n sh -c 'ip addr add 10.9.0.2/24 dev v1; ip link set v1 up; ip link set lo up'
/// ip addr add 10.9.0.1/24 dev v0; ip link set v0 up; ip link set lo up
/// nsenter -t $peer -n python3 -m http.server 8000 &
/// RMAP_VETH_PEER=10.9.0.2 RMAP_VETH_OPEN_PORT=8000 <test binary> --ignored raw_veth
/// ```
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CAP_NET_RAW and a veth peer (see comment)"]
async fn raw_veth_peer() {
    let Some(peer) = std::env::var("RMAP_VETH_PEER").ok() else {
        return;
    };
    let peer: Ipv4Addr = peer.parse().unwrap();
    let open: u16 = std::env::var("RMAP_VETH_OPEN_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let src = crate::raw::route_source(peer).unwrap();
    let absent = Ipv4Addr::from(u32::from(peer) + 1);

    let raw = crate::raw::RawScanner::open(ScanType::Connect, &patient()).unwrap();
    let quick = Timing {
        connect_timeout: Duration::from_millis(500),
        retries: 1,
        ..patient()
    };
    let up = raw.arp_ping(src, peer, &quick).await;
    assert!(
        matches!(up, Some(Some(_))),
        "ARP answer from {peer}: {up:?}"
    );
    let down = raw.arp_ping(src, absent, &quick).await;
    assert_eq!(down, Some(None), "no ARP answer from {absent}");

    let mut syn = typed(
        &peer.to_string(),
        &format!("{open},1"),
        patient(),
        ScanType::Syn,
    );
    syn.discovery = true;
    let out = run_scan(syn).await;
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
    assert_eq!(out.hosts()[0].2, HostState::Up);
    assert_eq!(out.open_ports(), [(IpAddr::V4(peer), open)]);
    assert_eq!(out.host_done()[0].1, 1, "port 1 answers RST");

    let udp = typed(&peer.to_string(), "9", udp_timing(), ScanType::Udp);
    let out = run_scan(udp).await;
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
    assert_eq!(out.host_done()[0].1, 1, "port 9 answers port-unreachable");

    let mut dead = typed(&absent.to_string(), "80", quick, ScanType::Syn);
    dead.discovery = true;
    let out = run_scan(dead).await;
    assert_eq!(out.hosts()[0].2, HostState::Down);
}

#[tokio::test(flavor = "multi_thread")]
async fn service_detection_reports_after_the_port() {
    let port = banner_server(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").await;
    let mut cfg = config("127.0.0.1", &port.to_string(), patient(), false);
    cfg.service_detection = true;
    let out = run_scan(cfg).await;
    assert!(out.finished());
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
    let port_at = out
        .events
        .iter()
        .position(|e| matches!(e, ScanEvent::Port { .. }))
        .expect("port event");
    let (service_at, service) = out
        .events
        .iter()
        .enumerate()
        .find_map(|(i, e)| match e {
            ScanEvent::Service {
                port: p,
                protocol,
                service,
                ..
            } if *p == port && *protocol == rmap_core::Protocol::Tcp => Some((i, service)),
            _ => None,
        })
        .expect("service event");
    assert!(service_at > port_at);
    assert_eq!(service.version_label().as_deref(), Some("OpenSSH 9.6p1"));
    assert_eq!(
        service.cpes,
        ["cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"]
    );
}

// ------------------------------------------------- vulnerability matching ---

#[tokio::test(flavor = "multi_thread")]
async fn vuln_matching_reports_a_real_cve_for_a_real_detected_service() {
    let port = banner_server(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").await;
    let mut cfg = config("127.0.0.1", &port.to_string(), patient(), false);
    cfg.service_detection = true;
    cfg.vuln_matching = true;
    let out = run_scan(cfg).await;
    assert!(out.finished());
    assert!(out.warnings().is_empty(), "{:?}", out.warnings());
    let service_at = out
        .events
        .iter()
        .position(|e| matches!(e, ScanEvent::Service { .. }))
        .expect("service event");
    let (vulns_at, findings) = out
        .events
        .iter()
        .enumerate()
        .find_map(|(i, e)| match e {
            ScanEvent::Vulnerabilities {
                port: p, findings, ..
            } if *p == port => Some((i, findings)),
            _ => None,
        })
        .expect("vulnerabilities event");
    assert!(
        vulns_at > service_at,
        "vulns must follow the service they're matched from"
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "CVE-2024-6387");
}

#[tokio::test(flavor = "multi_thread")]
async fn vuln_matching_sends_nothing_for_a_clean_version() {
    let port = banner_server(b"SSH-2.0-OpenSSH_9.9\r\n").await;
    let mut cfg = config("127.0.0.1", &port.to_string(), patient(), false);
    cfg.service_detection = true;
    cfg.vuln_matching = true;
    let out = run_scan(cfg).await;
    assert!(out.finished());
    assert!(
        !out.events
            .iter()
            .any(|e| matches!(e, ScanEvent::Vulnerabilities { .. })),
        "{:?}",
        out.events
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn vuln_matching_without_service_detection_sends_nothing() {
    let port = banner_server(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").await;
    let mut cfg = config("127.0.0.1", &port.to_string(), patient(), false);
    cfg.vuln_matching = true; // no service_detection: nothing to look up
    let out = run_scan(cfg).await;
    assert!(out.finished());
    assert!(
        !out.events
            .iter()
            .any(|e| matches!(e, ScanEvent::Vulnerabilities { .. }))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_service_events_when_detection_is_off() {
    let port = banner_server(b"SSH-2.0-OpenSSH_9.6\r\n").await;
    let out = run_scan(config("127.0.0.1", &port.to_string(), patient(), false)).await;
    assert_eq!(out.open_ports().len(), 1);
    assert!(
        !out.events
            .iter()
            .any(|e| matches!(e, ScanEvent::Service { .. }))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_cancels_service_detection() {
    // A silent service keeps detection busy for its whole budget.
    let port = banner_server(b"").await;
    let mut cfg = config("127.0.0.1", &port.to_string(), patient(), false);
    cfg.service_detection = true;
    let mut scan = Scan::start(&Handle::current(), cfg);
    // Wait for the port to be reported, then stop mid-detection.
    timeout(Duration::from_secs(10), async {
        while let Some(ev) = scan.events.recv().await {
            if matches!(ev, ScanEvent::Port { .. }) {
                break;
            }
        }
    })
    .await
    .expect("port reported");
    scan.stop();
    let rest = timeout(Duration::from_secs(5), async {
        let mut rest = Vec::new();
        while let Some(ev) = scan.events.recv().await {
            rest.push(ev);
        }
        rest
    })
    .await
    .expect("channel closes soon after stop");
    assert!(
        !rest
            .iter()
            .any(|e| matches!(e, ScanEvent::Service { .. } | ScanEvent::Finished { .. })),
        "{rest:?}"
    );
}

// ------------------------------------------------- exclusions and rate cap

fn excluding(targets: &str, exclude: &str, discovery: bool) -> ScanConfig {
    let timing = Timing {
        connect_timeout: Duration::from_millis(200),
        retries: 0,
        ..Timing::template(4)
    };
    ScanConfig {
        exclude: parse_targets(exclude).unwrap(),
        ..config(targets, "80", timing, discovery)
    }
}

fn started_hosts(out: &Outcome) -> u64 {
    match out.events.first() {
        Some(ScanEvent::Started { hosts, .. }) => *hosts,
        other => panic!("first event was {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn excluded_addresses_are_never_probed() {
    // Single address, a range, and an overlapping block, with discovery on
    // so pings are covered too.
    let out = run_scan(excluding(
        "192.0.2.0/29",
        "192.0.2.2, 192.0.2.4-192.0.2.5, 192.0.2.5/32",
        true,
    ))
    .await;
    assert!(out.finished());
    assert_eq!(started_hosts(&out), 5);
    let mut seen: Vec<IpAddr> = out.hosts().into_iter().map(|h| h.0).collect();
    seen.sort();
    let want: Vec<IpAddr> = [
        "192.0.2.0",
        "192.0.2.1",
        "192.0.2.3",
        "192.0.2.6",
        "192.0.2.7",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    assert_eq!(seen, want);
    assert_eq!(out.scan.progress.ratio(), 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn excluding_everything_finishes_with_a_clear_warning() {
    let out = run_scan(excluding("192.0.2.0/30, 192.0.2.9", "192.0.2.0/24", false)).await;
    assert!(out.finished());
    assert_eq!(started_hosts(&out), 0);
    assert!(out.hosts().is_empty());
    assert!(
        out.warnings().iter().any(|w| w.contains("exclude list")),
        "{:?}",
        out.warnings()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unresolvable_exclusion_stops_before_probing() {
    let out = run_scan(excluding("192.0.2.1", "no-such-host.invalid", false)).await;
    assert!(out.finished());
    assert!(out.hosts().is_empty());
    assert!(
        out.warnings()
            .iter()
            .any(|w| w.contains("no-such-host.invalid") && w.contains("nothing was scanned"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hostname_target_resolving_to_an_excluded_address_is_skipped() {
    let out = run_scan(excluding("localhost", "127.0.0.0/8, ::1", false)).await;
    assert!(out.finished());
    assert!(out.hosts().is_empty());
    assert!(
        out.warnings()
            .iter()
            .any(|w| w.contains("skipped localhost"))
    );
    assert_eq!(out.scan.progress.ratio(), 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn max_rate_caps_probe_starts() {
    // Open loopback ports answer at once, so without the cap these 20
    // probes finish in milliseconds. At 40/s the 20th can't start before
    // 19/40 s = 475 ms; only a lower bound is checked, so a slow machine
    // can't make this flaky.
    let mut ports = Vec::new();
    for _ in 0..20 {
        ports.push(listener().await.to_string());
    }
    let c = ScanConfig {
        max_rate: Some(40),
        ..config("127.0.0.1", &ports.join(","), patient(), false)
    };
    let started = Instant::now();
    let out = run_scan(c).await;
    let elapsed = started.elapsed();
    assert_eq!(out.open_ports().len(), 20);
    assert!(elapsed >= Duration::from_millis(450), "{elapsed:?}");
}

#[test]
fn describe_includes_scope_and_rate() {
    let c = ScanConfig {
        max_rate: Some(25),
        ..excluding("192.0.2.0/24", "192.0.2.7, plc.lan", false)
    };
    let d = c.describe();
    assert!(d.contains("exclude=[192.0.2.7,plc.lan]"), "{d}");
    assert!(d.contains("max_rate=25/s"), "{d}");
    assert!(
        config("192.0.2.1", "80", patient(), false)
            .describe()
            .contains("max_rate=unlimited")
    );
}
