//! UDP detection end to end, against loopback sockets that answer canned
//! replies the way real services do. No network access or privileges.

use std::net::SocketAddr;
use std::time::Duration;

use rmap_core::{DetectMethod, Protocol, Timing};
use tokio::net::UdpSocket;

use crate::udp::tests::{dns_answer, netbios_response, ntp_server, snmp_response, txt};
use crate::{Detected, Detector, udp};

/// A UDP server that answers each datagram with `reply(request)`, if any.
async fn serve(reply: fn(&[u8]) -> Option<Vec<u8>>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            if let Some(r) = reply(&buf[..n]) {
                let _ = socket.send_to(&r, from).await;
            }
        }
    });
    addr
}

fn quick() -> Timing {
    Timing {
        connect_timeout: Duration::from_millis(300),
        ..Timing::template(4)
    }
}

/// Run detection against `addr` as if it were on `port`.
async fn detect(addr: SocketAddr, port: u16) -> Detected {
    Detector::builtin()
        .detect_port(addr, Protocol::Udp, &quick(), port)
        .await
}

#[tokio::test]
async fn dns_version_names_the_product() {
    let addr = serve(|q| {
        // Only the version.bind query (class CH) gets the TXT answer.
        (q.ends_with(&[0, 16, 0, 3])).then(|| dns_answer(q, 0, &[(16, txt("dnsmasq-2.89"))]))
    })
    .await;
    let d = detect(addr, 53).await;
    assert!(d.answered);
    let s = d.service.unwrap();
    assert_eq!(
        (s.name.as_str(), s.product.as_deref(), s.version.as_deref()),
        ("dns", Some("dnsmasq"), Some("2.89"))
    );
    assert_eq!(s.method, DetectMethod::Probe);
    assert_eq!(s.cpes, ["cpe:2.3:a:thekelleys:dnsmasq:2.89:*:*:*:*:*:*:*"]);
    assert_eq!(s.info.as_deref(), Some("version.bind \"dnsmasq-2.89\""));
}

#[tokio::test]
async fn refused_version_still_identifies_dns() {
    let addr = serve(|q| Some(dns_answer(q, 5, &[]))).await;
    let s = detect(addr, 53).await.service.unwrap();
    assert_eq!((s.name.as_str(), s.product), ("dns", None));
    assert_eq!(
        s.info.as_deref(),
        Some("version.bind not disclosed (refused)")
    );
}

#[tokio::test]
async fn ntp_falls_back_to_the_client_request() {
    // Like a modern ntpd with `noquery`: mode 6 is ignored, mode 3 answered.
    let addr = serve(|q| (q.first()? & 7 == 3).then(|| ntp_server(2, [192, 0, 2, 7]))).await;
    let s = detect(addr, 123).await.service.unwrap();
    assert_eq!(s.name, "ntp");
    assert_eq!(
        s.info.as_deref(),
        Some("NTPv4, stratum 2, reference 192.0.2.7")
    );
}

#[tokio::test]
async fn snmp_v1_reply_is_read_by_the_v2c_rules() {
    // An agent that only speaks v1: the v2c request goes unanswered.
    let addr = serve(|q| {
        (q.get(4) == Some(&0)).then(|| snmp_response(0, b"Linux nas 6.1.0-18-amd64 #1 SMP x86_64"))
    })
    .await;
    let s = detect(addr, 161).await.service.unwrap();
    assert_eq!(s.name, "snmp");
    assert_eq!(s.os_hint.as_deref(), Some("Linux 6.1.0-18-amd64"));
    assert!(
        s.info
            .unwrap()
            .starts_with("SNMPv1, community \"public\" accepted: Linux nas"),
        "decoder summary kept"
    );
}

#[tokio::test]
async fn netbios_and_mdns_and_ssdp() {
    let nb = serve(|_| {
        Some(netbios_response(
            &[("PRINTSRV", 0, false), ("OFFICE", 0, true)],
            [2, 0, 0, 0, 0, 1],
        ))
    })
    .await;
    let s = detect(nb, 137).await.service.unwrap();
    assert_eq!(s.name, "netbios-ns");
    assert_eq!(
        s.info.as_deref(),
        Some("name PRINTSRV, workgroup OFFICE, MAC 02:00:00:00:00:01")
    );

    let mdns = serve(|q| Some(dns_answer(q, 0, &[(12, vec![0xc0, 12])]))).await;
    let s = detect(mdns, 5353).await.service.unwrap();
    assert_eq!(s.name, "mdns");

    let ssdp = serve(|q| {
        q.starts_with(b"M-SEARCH").then(|| {
            b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux/5.4 UPnP/1.1 MiniUPnPd/2.3.3\r\n\r\n"
                .to_vec()
        })
    })
    .await;
    let s = detect(ssdp, 1900).await.service.unwrap();
    assert_eq!(
        (s.name.as_str(), s.product.as_deref(), s.version.as_deref()),
        ("upnp", Some("MiniUPnPd"), Some("2.3.3"))
    );
    assert_eq!(
        s.cpes,
        ["cpe:2.3:a:miniupnp_project:miniupnpd:2.3.3:*:*:*:*:*:*:*"]
    );
}

#[tokio::test]
async fn silence_is_not_an_answer() {
    let addr = serve(|_| None).await;
    let d = detect(addr, 161).await;
    assert!(!d.answered);
    let s = d.service.unwrap();
    assert_eq!(
        (s.name.as_str(), s.method),
        ("snmp", DetectMethod::PortTable)
    );
}

#[tokio::test]
async fn garbage_reply_is_an_answer_but_unidentified() {
    let addr = serve(|_| Some(b"\xffnope".to_vec())).await;
    let d = detect(addr, 53).await;
    assert!(d.answered, "any datagram proves the port open");
    let s = d.service.unwrap();
    assert_eq!(s.method, DetectMethod::PortTable);
    assert_eq!(s.info.as_deref(), Some("unrecognised reply: \\xffnope"));
}

#[tokio::test]
async fn unknown_udp_ports_send_nothing() {
    let addr = serve(|_| Some(b"x".to_vec())).await;
    let d = detect(addr, 40000).await;
    assert_eq!(d, Detected::default());
}

#[test]
fn decoders_cover_the_udp_builtins() {
    use crate::db::{Builtin, Payload};
    for p in &Detector::builtin().database().probes {
        if p.protocol == Protocol::Udp
            && let Payload::Builtin(b) = p.payload
        {
            assert!(
                udp::decoder(b).is_some() || b == Builtin::SsdpSearch,
                "{} has no decoder",
                p.name
            );
        }
    }
}
