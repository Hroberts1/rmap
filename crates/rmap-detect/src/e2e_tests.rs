//! End-to-end detection against tokio listeners on loopback that behave
//! like real servers. No network access or privileges needed.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rmap_core::{DetectMethod, Protocol, Service, Timing};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::Detector;

/// How a fake server treats each connection.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Send this as soon as a client connects, then idle.
    Banner(&'static [u8]),
    /// Wait for a request that contains `needle`, then reply and close.
    Reply {
        needle: &'static [u8],
        reply: &'static [u8],
    },
    /// Wait for a TLS ClientHello and answer with this server flight.
    Tls,
    /// Accept and never say anything.
    Silent,
}

async fn serve(behaviour: Behaviour) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(handle(stream, behaviour));
        }
    });
    addr
}

async fn handle(mut s: TcpStream, behaviour: Behaviour) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    match behaviour {
        Behaviour::Banner(b) => {
            let _ = s.write_all(b).await;
            // Like a real daemon: keep the connection open for a while.
            let _ = tokio::time::timeout(Duration::from_secs(10), s.read(&mut chunk)).await;
        }
        Behaviour::Reply { needle, reply } => {
            while let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(10), s.read(&mut chunk)).await
            {
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(needle.len()).any(|w| w == needle) {
                    let _ = s.write_all(reply).await;
                    return;
                }
            }
        }
        Behaviour::Tls => {
            let Ok(n) = s.read(&mut chunk).await else {
                return;
            };
            if n >= 6 && chunk[0] == 0x16 && chunk[5] == 0x01 {
                let cert = crate::der::tests::fake_cert(
                    "router.example.test",
                    "Example Internal CA",
                    &["router.example.test", "10.0.0.1"],
                );
                let _ = s.write_all(&crate::tls::tests::server_flight(&cert)).await;
                let _ = tokio::time::timeout(Duration::from_secs(10), s.read(&mut chunk)).await;
            } else {
                // Not TLS: what an HTTPS server says to plain HTTP.
                let _ = s.write_all(b"\x15\x03\x03\x00\x02\x02\x46").await;
            }
        }
        Behaviour::Silent => {
            let _ = tokio::time::timeout(Duration::from_secs(30), s.read(&mut chunk)).await;
        }
    }
}

fn timing() -> Timing {
    Timing {
        connect_timeout: Duration::from_secs(2),
        ..Timing::template(4)
    }
}

/// Detect as if the service were on `port`.
async fn detect_as(addr: SocketAddr, port: u16) -> Service {
    Detector::builtin()
        .detect(addr, Protocol::Tcp, &timing(), port)
        .await
        .expect("something detected")
}

#[tokio::test]
async fn ssh_banner() {
    let addr = serve(Behaviour::Banner(
        b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    ))
    .await;
    let s = detect_as(addr, 22).await;
    assert_eq!(s.name, "ssh");
    assert_eq!(s.version_label().as_deref(), Some("OpenSSH 8.9p1"));
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu Linux"));
    assert_eq!(s.method, DetectMethod::Banner);
    assert_eq!(s.cpes, ["cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"]);
    assert!(s.confidence >= 8);
}

#[tokio::test]
async fn ssh_on_an_unusual_port() {
    // No probe claims port 40022, so the generic plan runs: banner first.
    let addr = serve(Behaviour::Banner(b"SSH-2.0-dropbear_2022.83\r\n")).await;
    let s = detect_as(addr, 40022).await;
    assert_eq!(s.version_label().as_deref(), Some("Dropbear sshd 2022.83"));
}

#[tokio::test]
async fn http_server_header() {
    let addr = serve(Behaviour::Reply {
        needle: b"\r\n\r\n",
        reply: b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
    })
    .await;
    let s = detect_as(addr, 8080).await;
    assert_eq!((s.name.as_str(), s.method), ("http", DetectMethod::Probe));
    assert_eq!(s.version_label().as_deref(), Some("nginx 1.24.0"));
    assert_eq!(s.cpes, ["cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"]);
}

#[tokio::test]
async fn http_on_an_unusual_port_after_a_silent_banner_wait() {
    let addr = serve(Behaviour::Reply {
        needle: b"GET / HTTP/1.0",
        reply: b"HTTP/1.0 200 OK\r\nServer: Apache/2.4.58 (Debian)\r\n\r\n<html></html>",
    })
    .await;
    let s = detect_as(addr, 40080).await;
    assert_eq!(s.version_label().as_deref(), Some("Apache httpd 2.4.58"));
    assert_eq!(s.os_hint.as_deref(), Some("Debian"));
}

#[tokio::test]
async fn smtp_banner() {
    let addr = serve(Behaviour::Banner(
        b"220 mx.example.test ESMTP Exim 4.96 Tue, 14 Nov 2023 10:00:00 +0000\r\n",
    ))
    .await;
    let s = detect_as(addr, 25).await;
    assert_eq!(s.name, "smtp");
    assert_eq!(s.version_label().as_deref(), Some("Exim smtpd 4.96"));
}

#[tokio::test]
async fn ftp_multiline_banner() {
    let addr = serve(Behaviour::Banner(
        b"220-FileZilla Server 1.7.3\r\n220 Please visit https://filezilla-project.org/\r\n",
    ))
    .await;
    let s = detect_as(addr, 21).await;
    assert_eq!(s.name, "ftp");
    assert_eq!(s.version_label().as_deref(), Some("FileZilla ftpd 1.7.3"));
    assert_eq!(
        s.cpes,
        ["cpe:2.3:a:filezilla-project:filezilla_server:1.7.3:*:*:*:*:*:*:*"]
    );
}

#[tokio::test]
async fn redis_info() {
    let addr = serve(Behaviour::Reply {
        needle: b"INFO\r\n",
        reply: b"+PONG\r\n$120\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 6.5.0 x86_64\r\n",
    })
    .await;
    let s = detect_as(addr, 6379).await;
    assert_eq!(s.name, "redis");
    assert_eq!(s.version_label().as_deref(), Some("Redis 7.2.4"));
    assert_eq!(s.os_hint.as_deref(), Some("Linux"));
}

#[tokio::test]
async fn tls_certificate_names() {
    let addr = serve(Behaviour::Tls).await;
    let s = detect_as(addr, 443).await;
    assert_eq!(s.name, "https");
    assert_eq!(
        s.info.as_deref(),
        Some(
            "TLSv1.2; CN=router.example.test; SAN=10.0.0.1; issuer=Example Internal CA; expires 2035-06-30"
        )
    );
    assert_eq!(s.method, DetectMethod::Probe);
}

#[tokio::test]
async fn silent_service_falls_back_to_the_port_table_within_budget() {
    let addr = serve(Behaviour::Silent).await;
    let fast = Timing::template(5);
    let started = Instant::now();
    let s = Detector::builtin()
        .detect(addr, Protocol::Tcp, &fast, 22)
        .await
        .unwrap();
    assert!(started.elapsed() < crate::budget(&fast) + Duration::from_secs(2));
    assert_eq!(
        (s.name.as_str(), s.method, s.confidence),
        ("ssh", DetectMethod::PortTable, 3)
    );
    assert!(s.cpes.is_empty());
}

#[tokio::test]
async fn unrecognised_reply_is_reported() {
    let addr = serve(Behaviour::Banner(b"\x00\x01WEIRD PROTOCOL v9\r\n")).await;
    let s = Detector::builtin()
        .detect(addr, Protocol::Tcp, &Timing::template(5), 40123)
        .await
        .unwrap();
    assert_eq!((s.name.as_str(), s.confidence), ("unknown", 0));
    assert_eq!(
        s.info.as_deref(),
        Some("unrecognised reply: \\x00\\x01WEIRD PROTOCOL v9\\r\\n")
    );
}

#[tokio::test]
async fn closed_port_gives_up_quickly() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    // Windows takes about 2 s to refuse on loopback, twice.
    let started = Instant::now();
    let s = Detector::builtin()
        .detect(addr, Protocol::Tcp, &timing(), 40999)
        .await;
    assert!(s.is_none());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn udp_uses_the_port_table_for_now() {
    let s = crate::detect([192, 0, 2, 1].into(), 53, Protocol::Udp, &timing())
        .await
        .unwrap();
    assert_eq!(
        (s.name.as_str(), s.method),
        ("dns", DetectMethod::PortTable)
    );
}
