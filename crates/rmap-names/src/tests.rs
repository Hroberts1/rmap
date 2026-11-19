//! Lookups against fake responders on loopback. No network, no root.

use super::*;
use crate::dns::tests::{encode_name, reply};

const WAIT: Duration = Duration::from_millis(500);

/// A UDP responder on 127.0.0.1 that answers each query with
/// `answer(query)`, sending every reply it returns in order.
async fn responder(answer: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            for r in answer(&buf[..n]) {
                let _ = sock.send_to(&r, from).await;
            }
        }
    });
    addr
}

fn lo() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

#[tokio::test]
async fn reverse_dns_reads_the_ptr_record() {
    let server = responder(|q| {
        // A stray reply with the wrong id first: it must be skipped.
        let mut stray = reply(q, &[(dns::TYPE_PTR, encode_name("wrong.lan"))]);
        stray[0] ^= 0xff;
        let good = reply(q, &[(dns::TYPE_PTR, encode_name("frontdesk.corp.lan."))]);
        vec![stray, good]
    })
    .await;
    let name = reverse_dns(lo(), server, WAIT).await.unwrap();
    assert_eq!(name.name, "frontdesk.corp.lan");
    assert_eq!(name.source, NameSource::Dns);
}

#[tokio::test]
async fn nxdomain_and_silence_give_no_name() {
    let nx = responder(|q| {
        let mut r = reply(q, &[]);
        r[3] |= 3; // NXDOMAIN
        vec![r]
    })
    .await;
    assert!(reverse_dns(lo(), nx, WAIT).await.is_none());

    let silent = responder(|_| Vec::new()).await;
    let started = std::time::Instant::now();
    assert!(
        reverse_dns(lo(), silent, Duration::from_millis(150))
            .await
            .is_none()
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn hostile_names_are_cleaned() {
    let server = responder(|q| {
        let mut name = vec![10];
        name.extend_from_slice(b"pc\x1b[31mred");
        name.push(0);
        vec![reply(q, &[(dns::TYPE_PTR, name)])]
    })
    .await;
    let name = reverse_dns(lo(), server, WAIT).await.unwrap();
    assert_eq!(name.name, "pc?[31mred");
}

/// A NetBIOS node status reply table: a group name, then the workstation
/// name, then a non-workstation unique name.
fn name_table() -> Vec<u8> {
    let mut data = vec![3u8];
    for (name, suffix, group) in [
        ("WORKGROUP", 0u8, true),
        ("FRONTDESK", 0, false),
        ("FRONTDESK", 0x20, false),
    ] {
        let mut entry = [b' '; 18];
        entry[..name.len()].copy_from_slice(name.as_bytes());
        entry[15] = suffix;
        entry[16] = if group { 0x84 } else { 0x04 };
        entry[17] = 0;
        data.extend_from_slice(&entry);
    }
    data.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // MAC in the stats block
    data
}

#[tokio::test]
async fn netbios_reads_the_workstation_name() {
    let server = responder(|q| vec![reply(q, &[(dns::TYPE_NBSTAT, name_table())])]).await;
    let name = netbios_at(server, WAIT).await.unwrap();
    assert_eq!(
        (name.name.as_str(), name.source),
        ("FRONTDESK", NameSource::Netbios)
    );
}

#[test]
fn netbios_tables_never_panic() {
    let table = name_table();
    for n in 0..table.len() {
        let _ = workstation_name(&table[..n]);
    }
    assert_eq!(workstation_name(&[200]), None);
    assert_eq!(workstation_name(&table).as_deref(), Some("FRONTDESK"));
}

#[tokio::test]
async fn mdns_accepts_a_zero_id_reply() {
    let server = responder(|q| {
        let mut r = reply(q, &[(dns::TYPE_PTR, encode_name("Office-Printer.local"))]);
        r[0] = 0;
        r[1] = 0;
        vec![r]
    })
    .await;
    let name = mdns_at(lo(), server, WAIT).await.unwrap();
    assert_eq!(
        (name.name.as_str(), name.source),
        ("Office-Printer.local", NameSource::Mdns)
    );
}

#[tokio::test]
async fn mdns_ignores_ptr_records_for_other_names() {
    let server = responder(|q| {
        // An answer owned by a different name (a service list, say).
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r[7] = 1;
        r.extend_from_slice(&encode_name("_services._dns-sd._udp.local"));
        let data = encode_name("_http._tcp.local");
        r.extend_from_slice(&dns::TYPE_PTR.to_be_bytes());
        r.extend_from_slice(&dns::CLASS_IN.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(&data);
        vec![r]
    })
    .await;
    assert!(
        mdns_at(lo(), server, Duration::from_millis(200))
            .await
            .is_none()
    );
}

#[test]
fn resolv_conf() {
    let conf = "# comment\nsearch corp.lan\nnameserver fe80::1%eth0\nnameserver 10.0.0.2\n";
    assert_eq!(
        parse_resolv_conf(conf),
        Some("[fe80::1]:53".parse().unwrap())
    );
    assert_eq!(
        parse_resolv_conf("nameserver nonsense\nnameserver 127.0.0.53"),
        Some("127.0.0.53:53".parse().unwrap())
    );
    assert_eq!(parse_resolv_conf("options edns0"), None);
}

#[test]
fn windows_dns_entries() {
    let pad = |s: &str| {
        let mut b = [0u8; 16];
        b[..s.len()].copy_from_slice(s.as_bytes());
        b
    };
    let (zero, junk, good) = (pad("0.0.0.0"), pad("not an ip"), pad("10.0.0.10"));
    assert_eq!(
        first_dns_entry([&zero[..], &junk[..], &good[..]]),
        Some("10.0.0.10:53".parse().unwrap())
    );
    // No NUL at all, a bad UTF-8 byte, an empty list.
    assert_eq!(first_dns_entry([&b"192.168.100.200x"[..]]), None);
    assert_eq!(first_dns_entry([&[0xffu8, 0][..]]), None);
    assert_eq!(first_dns_entry(std::iter::empty()), None);
}

// Needs a configured IPv4 DNS server; a bare CI runner may have none.
#[cfg(windows)]
#[test]
#[ignore]
fn windows_system_dns_found() {
    assert!(system_dns_server().is_some());
}

#[test]
fn rank_orders_and_dedupes() {
    let n = |s, src| HostName::new(s, src).unwrap();
    let ranked = rank(vec![
        n("printer.local", NameSource::Mdns),
        n("FRONTDESK", NameSource::Netbios),
        n("frontdesk", NameSource::Mdns),
        n("frontdesk.corp.lan", NameSource::Dns),
    ]);
    let got: Vec<String> = ranked.iter().map(|h| h.to_string()).collect();
    assert_eq!(
        got,
        [
            "frontdesk.corp.lan (DNS)",
            "FRONTDESK (NetBIOS)",
            "printer.local (mDNS)"
        ]
    );
}
