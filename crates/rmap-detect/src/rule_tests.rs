//! One realistic response per match rule in `probes.txt`. The final check
//! fails if any rule has no test, so new rules can't land untested.
//!
//! The banners are written for these tests from protocol documentation and
//! the shapes real servers use; host names and addresses are made up.

use std::collections::BTreeSet;

use rmap_core::Service;

use crate::db::Database;

struct Rules {
    db: Database,
    hit: BTreeSet<usize>,
}

impl Rules {
    fn new() -> Rules {
        Rules {
            db: Database::parse(crate::db::BUILTIN).expect("probes.txt parses"),
            hit: BTreeSet::new(),
        }
    }

    /// Match `response` to probe `probe` and check the basics.
    fn check(
        &mut self,
        probe: &str,
        response: &[u8],
        name: &str,
        product: Option<&str>,
        version: Option<&str>,
    ) -> Service {
        let index = self
            .db
            .probe(probe)
            .unwrap_or_else(|| panic!("no probe {probe}"));
        let Some(m) = self.db.identify(index, response) else {
            panic!(
                "{probe}: nothing matched {:?}",
                crate::escape(response, 200)
            );
        };
        let s = m.service;
        let at = format!(
            "rule at line {} for {:?}",
            m.rule.line,
            crate::escape(response, 80)
        );
        assert_eq!(s.name, name, "{at}");
        assert_eq!(s.product.as_deref(), product, "{at}");
        assert_eq!(s.version.as_deref(), version, "{at}");
        self.hit.insert(m.rule.id);
        s
    }
}

fn mysql_greeting(version: &str) -> Vec<u8> {
    let mut body = vec![0x0a];
    body.extend_from_slice(version.as_bytes());
    body.push(0);
    body.extend_from_slice(&[0x0b, 0, 0, 0]); // thread id
    body.extend_from_slice(b"\x26\x3a\x7b\x0a\x5c\x31\x00\x0d"); // salt; note the \n
    body.extend_from_slice(&[0xff, 0xf7, 0x2d, 0x02, 0, 0xff, 0x81, 0x15]);
    body.extend_from_slice(&[0; 10]);
    let mut p = (body.len() as u32).to_le_bytes()[..3].to_vec();
    p.push(0);
    p.extend_from_slice(&body);
    p
}

fn mongodb_reply(version: Option<&str>) -> Vec<u8> {
    let mut doc = Vec::new();
    if let Some(v) = version {
        doc.push(0x02);
        doc.extend_from_slice(b"version\0");
        doc.extend_from_slice(&((v.len() + 1) as i32).to_le_bytes());
        doc.extend_from_slice(v.as_bytes());
        doc.push(0);
    }
    doc.push(0x01);
    doc.extend_from_slice(b"ok\0");
    doc.extend_from_slice(&1f64.to_le_bytes());
    doc.push(0);
    let mut msg = ((doc.len() + 4 + 21) as i32).to_le_bytes().to_vec();
    msg.extend_from_slice(&[0x10, 0x20, 0, 0, 0x70, 0x61, 0x6d, 0x72]); // ids
    msg.extend_from_slice(&2013i32.to_le_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0, 0]);
    msg.extend_from_slice(&((doc.len() + 4) as i32).to_le_bytes());
    msg.extend_from_slice(&doc);
    msg
}

#[test]
fn every_rule_matches_its_banner() {
    let mut r = Rules::new();

    // ---------------------------------------------------------- SSH ---
    let s = r.check(
        "banner",
        b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n",
        "ssh",
        Some("OpenSSH"),
        Some("8.1"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Windows"));
    let s = r.check(
        "banner",
        b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
        "ssh",
        Some("OpenSSH"),
        Some("8.9p1"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu Linux"));
    assert_eq!(s.info.as_deref(), Some("protocol 2.0; Ubuntu-3ubuntu0.6"));
    let s = r.check(
        "banner",
        b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n",
        "ssh",
        Some("OpenSSH"),
        Some("9.2p1"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Debian Linux"));
    let s = r.check(
        "banner",
        b"SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2\r\n",
        "ssh",
        Some("OpenSSH"),
        Some("7.9p1"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Raspbian Linux"));
    let s = r.check(
        "banner",
        b"SSH-2.0-OpenSSH_9.3 FreeBSD-20230719\r\n",
        "ssh",
        Some("OpenSSH"),
        Some("9.3"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("FreeBSD"));
    let s = r.check(
        "banner",
        b"SSH-2.0-OpenSSH_7.4\r\n",
        "ssh",
        Some("OpenSSH"),
        Some("7.4"),
    );
    assert_eq!(s.info.as_deref(), Some("protocol 2.0"));
    assert_eq!(s.os_hint, None);
    r.check(
        "banner",
        b"SSH-2.0-dropbear_2022.83\r\n",
        "ssh",
        Some("Dropbear sshd"),
        Some("2022.83"),
    );
    let s = r.check("banner", b"SSH-1.99-Cisco-1.25\r\n", "ssh", None, None);
    assert_eq!(s.info.as_deref(), Some("protocol 1.99; Cisco-1.25"));

    // ---------------------------------------------------------- FTP ---
    r.check(
        "banner",
        b"220 (vsFTPd 3.0.5)\r\n",
        "ftp",
        Some("vsftpd"),
        Some("3.0.5"),
    );
    let s = r.check(
        "banner",
        b"220 ProFTPD 1.3.5e Server (Debian) [::ffff:10.0.0.5]\r\n",
        "ftp",
        Some("ProFTPD"),
        Some("1.3.5e"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Debian Linux"));
    let s = r.check(
        "banner",
        b"220 ProFTPD Server (ProFTPD Default Installation) [10.0.0.5]\r\n",
        "ftp",
        Some("ProFTPD"),
        None,
    );
    assert_eq!(s.info.as_deref(), Some("ProFTPD Default Installation"));
    r.check(
        "banner",
        b"220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n220-You are user number 1 of 50 allowed.\r\n",
        "ftp",
        Some("Pure-FTPd"),
        None,
    );
    let s = r.check(
        "banner",
        b"220-FileZilla Server 1.7.3\r\n220 Please visit https://filezilla-project.org/\r\n",
        "ftp",
        Some("FileZilla ftpd"),
        Some("1.7.3"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Windows"));
    r.check(
        "banner",
        b"220-FileZilla Server version 0.9.60 beta\r\n220-written by Tim Kosse\r\n",
        "ftp",
        Some("FileZilla ftpd"),
        Some("0.9.60 beta"),
    );
    r.check(
        "banner",
        b"220 ZBR-48213 Version V84.20.10Z ready.\r\n",
        "ftp",
        Some("Zebra print server"),
        Some("V84.20.10Z"),
    );
    r.check(
        "banner",
        b"220 Microsoft FTP Service\r\n",
        "ftp",
        Some("Microsoft ftpd"),
        None,
    );
    r.check(
        "banner",
        b"220 Welcome to the example.test FTP archive\r\n",
        "ftp",
        None,
        None,
    );

    // --------------------------------------------------------- SMTP ---
    let s = r.check(
        "banner",
        b"220 mail.contoso.test Microsoft ESMTP MAIL Service ready at Tue, 14 Nov 2023 10:00:00 +0000\r\n",
        "smtp",
        Some("Microsoft Exchange smtpd"),
        None,
    );
    assert_eq!(
        s.cpes,
        Vec::<String>::new(),
        "CPEs are added by Detector::analyze"
    );
    r.check(
        "banner",
        b"220 mx.contoso.test Microsoft ESMTP MAIL Service, Version: 8.0.3790.4675 ready at  Tue, 14 Nov 2023\r\n",
        "smtp",
        Some("Microsoft Exchange smtpd"),
        Some("8.0.3790.4675"),
    );
    let s = r.check(
        "banner",
        b"220 mail.example.test ESMTP Postfix (Ubuntu)\r\n",
        "smtp",
        Some("Postfix smtpd"),
        None,
    );
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu"));
    assert_eq!(s.info.as_deref(), Some("host mail.example.test"));
    let s = r.check(
        "banner",
        b"220 mx.example.test ESMTP Exim 4.96 Tue, 14 Nov 2023 10:00:00 +0000\r\n",
        "smtp",
        Some("Exim smtpd"),
        Some("4.96"),
    );
    assert_eq!(s.info.as_deref(), Some("host mx.example.test"));
    let s = r.check(
        "banner",
        b"220 relay.example.test ESMTP Sendmail 8.15.2/8.15.2; Tue, 14 Nov 2023 10:00:00 GMT\r\n",
        "smtp",
        Some("Sendmail"),
        Some("8.15.2"),
    );
    assert_eq!(
        s.info.as_deref(),
        Some("host relay.example.test; config 8.15.2")
    );
    r.check(
        "banner",
        b"220 smtp.example.test ESMTP Haraka ready\r\n",
        "smtp",
        None,
        None,
    );

    // ---------------------------------------------------- POP3, IMAP ---
    let s = r.check(
        "banner",
        b"+OK Dovecot (Ubuntu) ready.\r\n",
        "pop3",
        Some("Dovecot pop3d"),
        None,
    );
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu"));
    r.check(
        "banner",
        b"+OK Dovecot ready.\r\n",
        "pop3",
        Some("Dovecot pop3d"),
        None,
    );
    r.check(
        "banner",
        b"+OK Hello there.\r\n",
        "pop3",
        Some("Courier pop3d"),
        None,
    );
    r.check(
        "banner",
        b"+OK POP3 server ready <1896.697170952@mail.example.test>\r\n",
        "pop3",
        None,
        None,
    );
    let s = r.check(
        "banner",
        b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot (Debian) ready.\r\n",
        "imap",
        Some("Dovecot imapd"),
        None,
    );
    assert_eq!(s.os_hint.as_deref(), Some("Debian"));
    r.check(
        "banner",
        b"* OK [CAPABILITY IMAP4rev1 UIDPLUS CHILDREN NAMESPACE SORT QUOTA IDLE STARTTLS] Courier-IMAP ready. Copyright 1998-2018 Double Precision, Inc.  See COPYING for distribution information.\r\n",
        "imap",
        Some("Courier Imapd"),
        None,
    );
    r.check(
        "banner",
        b"* OK IMAP4rev1 Service Ready\r\n",
        "imap",
        None,
        None,
    );

    // ------------------------------------------------ MySQL, MariaDB ---
    let s = r.check(
        "banner",
        &mysql_greeting("5.5.5-10.6.16-MariaDB-0ubuntu0.22.04.1"),
        "mysql",
        Some("MariaDB"),
        Some("10.6.16"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu Linux"));
    let s = r.check(
        "banner",
        &mysql_greeting("11.2.2-MariaDB-1:11.2.2+maria~ubu2204"),
        "mysql",
        Some("MariaDB"),
        Some("11.2.2"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu Linux"));
    let s = r.check(
        "banner",
        &mysql_greeting("5.5.5-10.11.6-MariaDB-0+deb12u1"),
        "mysql",
        Some("MariaDB"),
        Some("10.11.6"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Debian Linux"));
    let s = r.check(
        "banner",
        &mysql_greeting("5.5.5-10.5.22-MariaDB"),
        "mysql",
        Some("MariaDB"),
        Some("10.5.22"),
    );
    assert_eq!((s.info.as_deref(), s.os_hint), (Some("MariaDB"), None));
    let s = r.check(
        "banner",
        &mysql_greeting("8.0.36-0ubuntu0.22.04.1"),
        "mysql",
        Some("MySQL"),
        Some("8.0.36"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu Linux"));
    let s = r.check(
        "banner",
        &mysql_greeting("8.0.35"),
        "mysql",
        Some("MySQL"),
        Some("8.0.35"),
    );
    assert_eq!(s.info, None);
    r.check(
        "banner",
        &mysql_greeting("5.7.44-log"),
        "mysql",
        Some("MySQL"),
        Some("5.7.44"),
    );
    r.check(
        "banner",
        b"\x45\x00\x00\x00\xff\x6a\x04Host '10.0.0.9' is not allowed to connect to this MySQL server",
        "mysql",
        Some("MySQL"),
        None,
    );
    r.check(
        "banner",
        b"\x47\x00\x00\x00\xff\x6a\x04Host '10.0.0.9' is not allowed to connect to this MariaDB server",
        "mysql",
        Some("MariaDB"),
        None,
    );
    r.check(
        "banner",
        b"\x17\x00\x00\x00\xff\x10\x04Too many connections",
        "mysql",
        None,
        None,
    );

    // ----------------------------------------------- VNC and telnet ---
    let s = r.check(
        "banner",
        b"RFB 003.889\n",
        "vnc",
        Some("Apple remote desktop vnc"),
        None,
    );
    assert_eq!(s.os_hint.as_deref(), Some("macOS"));
    let s = r.check("banner", b"RFB 003.008\n", "vnc", None, None);
    assert_eq!(s.info.as_deref(), Some("RFB protocol 003.008"));
    r.check(
        "banner",
        b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27",
        "telnet",
        None,
        None,
    );

    // --------------------------------------------------------- HTTP ---
    r.check(
        "http-get",
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 540\r\n\r\n{\n  \"name\" : \"node-1\",\n  \"cluster_name\" : \"docker-cluster\",\n  \"version\" : {\n    \"number\" : \"8.11.1\",\n    \"build_flavor\" : \"default\"\n  },\n  \"tagline\" : \"You Know, for Search\"\n}\n",
        "http",
        Some("Elasticsearch"),
        Some("8.11.1"),
    );
    r.check(
        "http-get",
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"security\" charset=\"UTF-8\"\r\nX-elastic-product: Elasticsearch\r\ncontent-length: 0\r\n\r\n",
        "http",
        Some("Elasticsearch"),
        None,
    );
    let s = r.check(
        "http-get",
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nDate: Tue, 14 Nov 2023 10:00:00 GMT\r\n\r\n",
        "http",
        Some("nginx"),
        Some("1.18.0"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Ubuntu"));
    r.check(
        "http-get",
        b"HTTP/1.1 301 Moved\r\nserver: nginx\r\n\r\n",
        "http",
        Some("nginx"),
        None,
    );
    r.check(
        "http-get",
        b"HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n",
        "http",
        Some("Apache Tomcat Coyote"),
        Some("1.1"),
    );
    let s = r.check(
        "http-get",
        b"HTTP/1.1 200 OK\r\nDate: Tue, 14 Nov 2023 10:00:00 GMT\r\nServer: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.33\r\n\r\n",
        "http",
        Some("Apache httpd"),
        Some("2.4.6"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("CentOS"));
    assert_eq!(s.info.as_deref(), Some("OpenSSL/1.0.2k-fips PHP/7.4.33"));
    r.check(
        "http-get",
        b"HTTP/1.0 403 Forbidden\r\nServer: Apache\r\n\r\n",
        "http",
        Some("Apache httpd"),
        None,
    );
    let s = r.check(
        "http-get",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\n\r\n",
        "http",
        Some("Microsoft IIS httpd"),
        Some("10.0"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Windows"));
    r.check(
        "http-get",
        b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=us-ascii\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
        "http",
        Some("Microsoft HTTPAPI httpd"),
        Some("2.0"),
    );
    r.check(
        "http-get",
        b"HTTP/1.0 200 OK\r\nServer: lighttpd/1.4.73\r\n\r\n",
        "http",
        Some("lighttpd"),
        Some("1.4.73"),
    );
    r.check(
        "http-get",
        b"HTTP/1.1 308 Permanent Redirect\r\nServer: Caddy\r\n\r\n",
        "http",
        Some("Caddy"),
        None,
    );
    r.check(
        "http-get",
        b"HTTP/1.1 200 OK\r\nServer: gunicorn/20.1.0\r\n\r\n",
        "http",
        Some("gunicorn"),
        Some("20.1.0"),
    );
    r.check(
        "http-get",
        b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n",
        "http",
        Some("cloudflare"),
        None,
    );
    r.check(
        "http-get",
        b"HTTP/1.0 302 Found\r\nLocation: /login\r\n\r\n",
        "http",
        None,
        None,
    );
    // Falls back to other probes' rules for mismatched protocols.
    r.check(
        "http-get",
        b"SSH-2.0-OpenSSH_9.6\r\n",
        "ssh",
        Some("OpenSSH"),
        Some("9.6"),
    );
    r.check(
        "http-get",
        b"RTSP/1.0 400 Bad Request\r\n\r\n",
        "rtsp",
        None,
        None,
    );

    // ---------------------------------------------------- RTSP, SIP ---
    r.check(
        "rtsp-options",
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: GStreamer RTSP server\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n",
        "rtsp",
        Some("GStreamer RTSP server"),
        None,
    );
    r.check(
        "rtsp-options",
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Wowza Streaming Engine/4.8.26\r\n\r\n",
        "rtsp",
        Some("Wowza Streaming Engine"),
        Some("4.8.26"),
    );
    r.check(
        "rtsp-options",
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n",
        "rtsp",
        None,
        None,
    );
    r.check(
        "sip-options",
        b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP rmap.invalid:5060;branch=z9hG4bK-rmap-1\r\nServer: Asterisk PBX 18.10.0~dfsg+~cs6.10.40431411-1\r\nContent-Length: 0\r\n\r\n",
        "sip",
        Some("Asterisk"),
        Some("18.10.0~dfsg"),
    );
    r.check(
        "sip-options",
        b"SIP/2.0 200 OK\r\nCSeq: 1 OPTIONS\r\nUser-Agent: FPBX-16.0.40(18.13.0)\r\n\r\n",
        "sip",
        Some("FPBX-16.0.40(18.13.0)"),
        None,
    );
    r.check(
        "sip-options",
        b"SIP/2.0 404 Not Found\r\nCSeq: 1 OPTIONS\r\n\r\n",
        "sip",
        None,
        None,
    );

    // -------------------------------------------------------- Redis ---
    let s = r.check(
        "redis",
        b"+PONG\r\n$5012\r\n# Server\r\nredis_version:7.2.4\r\nserver_name:valkey\r\nvalkey_version:8.0.1\r\nredis_git_sha1:00000000\r\nos:Linux 6.5.0-14-generic x86_64\r\n",
        "redis",
        Some("Valkey"),
        Some("8.0.1"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Linux"));
    let s = r.check(
        "redis",
        b"+PONG\r\n$3803\r\n# Server\r\nredis_version:7.2.4\r\nredis_git_sha1:00000000\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\narch_bits:64\r\n",
        "redis",
        Some("Redis"),
        Some("7.2.4"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Linux"));
    r.check(
        "redis",
        b"+PONG\r\n$3803\r\n# Server\r\nredis_version:6.0.16\r\nredis_git",
        "redis",
        Some("Redis"),
        Some("6.0.16"),
    );
    let s = r.check(
        "redis",
        b"-NOAUTH Authentication required.\r\n-NOAUTH Authentication required.\r\n",
        "redis",
        Some("Redis"),
        None,
    );
    assert_eq!(s.info.as_deref(), Some("authentication required"));
    r.check(
        "redis",
        b"-DENIED Redis is running in protected mode because protected mode is enabled\r\n",
        "redis",
        Some("Redis"),
        None,
    );
    r.check("redis", b"+PONG\r\n", "redis", Some("Redis"), None);

    // ------------------------------------------- Memcached, MongoDB ---
    r.check(
        "memcached",
        b"VERSION 1.6.21\r\n",
        "memcached",
        Some("Memcached"),
        Some("1.6.21"),
    );
    r.check(
        "mongodb",
        &mongodb_reply(Some("7.0.5")),
        "mongodb",
        Some("MongoDB"),
        Some("7.0.5"),
    );
    r.check(
        "mongodb",
        &mongodb_reply(None),
        "mongodb",
        Some("MongoDB"),
        None,
    );

    // --------------------------------------------------- PostgreSQL ---
    let s = r.check(
        "postgres",
        b"R\x00\x00\x00\x08\x00\x00\x00\x00S\x00\x00\x00\x1aapplication_name\x00\x00S\x00\x00\x00\x2aserver_version\x0016.1 (Debian 16.1-1.pgdg120+1)\x00Z\x00\x00\x00\x05I",
        "postgresql",
        Some("PostgreSQL"),
        Some("16.1"),
    );
    assert_eq!(
        s.info.as_deref(),
        Some("Debian 16.1-1.pgdg120+1; no authentication required")
    );
    r.check(
        "postgres",
        b"R\x00\x00\x00\x17\x00\x00\x00\x0aSCRAM-SHA-256\x00\x00",
        "postgresql",
        Some("PostgreSQL"),
        None,
    );
    r.check(
        "postgres",
        b"R\x00\x00\x00\x0c\x00\x00\x00\x05\xab\xcd\xef\x01",
        "postgresql",
        Some("PostgreSQL"),
        None,
    );
    let s = r.check(
        "postgres",
        b"E\x00\x00\x00\x6bSFATAL\x00VFATAL\x00C28000\x00Mno pg_hba.conf entry for host \"10.0.0.9\", user \"rmap\", database \"rmap\", no encryption\x00Fauth.c\x00L543\x00\x00",
        "postgresql",
        Some("PostgreSQL"),
        None,
    );
    assert!(s.info.unwrap().starts_with("error: no pg_hba.conf entry"));

    // ------------------------------------------- SMB, RDP, AMQP, MQTT ---
    let mut smb2 = b"\x00\x00\x00\xf8\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00".to_vec();
    smb2.extend_from_slice(&[0; 60]);
    let s = r.check("smb", &smb2, "smb", None, None);
    assert_eq!(s.info.as_deref(), Some("SMB2 or later"));
    r.check(
        "smb",
        b"\x00\x00\x00\x55\xffSMBr\x00\x00\x00\x00\x98\x53\xc8",
        "smb",
        None,
        None,
    );
    r.check("smb", b"\x83\x00\x00\x01\x8f", "netbios-ssn", None, None);
    r.check(
        "rdp",
        b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x02\x00\x00\x00",
        "rdp",
        None,
        None,
    );
    r.check(
        "amqp",
        b"\x01\x00\x00\x00\x00\x01\xfc\x00\x0a\x00\x0a\x00\x09\x00\x00\x01\xd7\x0ccapabilitiesF\x00\x00\x00\x00\x0ccluster_nameS\x00\x00\x00\x0drabbit@broker\x08platformS\x00\x00\x00\x11Erlang/OTP 26.1.2\x07productS\x00\x00\x00\x08RabbitMQ\x07versionS\x00\x00\x00\x073.12.10\x01\xce",
        "amqp",
        Some("RabbitMQ"),
        Some("3.12.10"),
    );
    r.check(
        "amqp",
        b"\x01\x00\x00\x00\x00\x00\x40\x00\x0a\x00\x0a\x00\x09\x00\x00\x00\x00\x00\x00\x00\x05PLAIN\x00\x00\x00\x05en_US\xce",
        "amqp",
        None,
        None,
    );
    r.check("amqp", b"AMQP\x00\x00\x09\x01", "amqp", None, None);
    let s = r.check("mqtt", b"\x20\x02\x00\x00", "mqtt", None, None);
    assert_eq!(
        s.info.as_deref(),
        Some("connection accepted without credentials")
    );
    let s = r.check("mqtt", b"\x20\x02\x00\x05", "mqtt", None, None);
    assert_eq!(s.info.as_deref(), Some("authentication required"));
    r.check("mqtt", b"\x20\x02\x00\x02", "mqtt", None, None);

    // ----------------------------------------------------------- UDP ---
    // Rules on decoded probes see the text the decoder pulled out.
    r.check(
        "dns-version",
        b"dnsmasq-2.90",
        "dns",
        Some("dnsmasq"),
        Some("2.90"),
    );
    r.check(
        "dns-version",
        b"9.18.24-1ubuntu1-Ubuntu",
        "dns",
        Some("ISC BIND"),
        Some("9.18.24"),
    );
    r.check(
        "dns-version",
        b"9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.13",
        "dns",
        Some("ISC BIND"),
        Some("9.11.4 P2"),
    );
    r.check(
        "dns-version",
        b"unbound 1.17.1",
        "dns",
        Some("Unbound"),
        Some("1.17.1"),
    );
    r.check(
        "dns-version",
        b"PowerDNS Recursor 4.8.4 (built Jan 10 2024 08:31:19 by root@localhost)",
        "dns",
        Some("PowerDNS Recursor"),
        Some("4.8.4"),
    );
    r.check(
        "dns-version",
        b"PowerDNS Authoritative Server 4.7.3 (built Dec 12 2022)",
        "dns",
        Some("PowerDNS Authoritative Server"),
        Some("4.7.3"),
    );
    r.check(
        "dns-version",
        b"Knot DNS 3.2.6",
        "dns",
        Some("Knot DNS"),
        Some("3.2.6"),
    );
    let s = r.check(
        "dns-version",
        b"Microsoft DNS 10.0.17763 (4A6339E8)",
        "dns",
        Some("Microsoft DNS"),
        Some("10.0.17763"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Windows"));
    r.check(
        "ntp-readvar",
        b"version=\"ntpd ntpsec-1.2.2 2023-04-06T00:00:00Z\", processor=\"x86_64\"",
        "ntp",
        Some("NTPsec"),
        Some("1.2.2"),
    );
    let s = r.check(
        "ntp-readvar",
        b"version=\"ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)\",\r\nprocessor=\"x86_64\", system=\"Linux/5.10.0-28-amd64\", leap=0, stratum=2",
        "ntp",
        Some("ntpd"),
        Some("4.2.8p15"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Linux/5.10.0-28-amd64"));
    r.check(
        "ntp-readvar",
        b"version=\"ntpd 4.2.6p5@1.2349-o Fri Apr 13 2018\", processor=\"x86_64\"",
        "ntp",
        Some("ntpd"),
        Some("4.2.6p5"),
    );
    let s = r.check(
        "snmp-v2c",
        b"Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\r\nTechnical Support: http://www.cisco.com/techsupport",
        "snmp",
        Some("Cisco IOS"),
        Some("15.0(2)SE11"),
    );
    assert_eq!(s.os_hint.as_deref(), Some("Cisco IOS"));
    let s = r.check(
        "snmp-v1",
        b"Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)",
        "snmp",
        None,
        None,
    );
    assert_eq!(s.os_hint.as_deref(), Some("Windows 6.3"));
    let s = r.check(
        "snmp-v2c",
        b"Linux gw01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64",
        "snmp",
        None,
        None,
    );
    assert_eq!(s.os_hint.as_deref(), Some("Linux 5.15.0-91-generic"));
    let s = r.check(
        "snmp-v2c",
        b"FreeBSD fw.example.test 13.2-RELEASE-p4 FreeBSD 13.2-RELEASE-p4 amd64",
        "snmp",
        None,
        None,
    );
    assert_eq!(s.os_hint.as_deref(), Some("FreeBSD 13.2-RELEASE-p4"));
    r.check(
        "ssdp",
        b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: upnp:rootdevice\r\nUSN: uuid:5a1c0e2b::upnp:rootdevice\r\nEXT:\r\nSERVER: AsusWRT/386 UPnP/1.1 MiniUPnPd/2.2.0\r\nLOCATION: http://192.0.2.1:5431/rootDesc.xml\r\n\r\n",
        "upnp",
        Some("MiniUPnPd"),
        Some("2.2.0"),
    );
    r.check(
        "ssdp",
        b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nServer: Linux/3.10.104, UPnP/1.0, Portable SDK for UPnP devices/1.6.22\r\n\r\n",
        "upnp",
        Some("libupnp"),
        Some("1.6.22"),
    );
    let s = r.check(
        "ssdp",
        b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\nSERVER: Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0\r\n\r\n",
        "upnp",
        None,
        None,
    );
    assert_eq!(
        s.info.as_deref(),
        Some("Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0")
    );
    r.check(
        "ssdp",
        b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n",
        "upnp",
        None,
        None,
    );

    // ------------------------------------------------------ coverage ---
    let all: BTreeSet<usize> = r.db.rules().map(|rule| rule.id).collect();
    let missing: Vec<usize> =
        r.db.rules()
            .filter(|rule| !r.hit.contains(&rule.id))
            .map(|rule| rule.line)
            .collect();
    assert!(
        missing.is_empty(),
        "rules without a test, by probes.txt line: {missing:?}"
    );
    assert_eq!(r.hit, all);
}

#[test]
fn near_misses_do_not_match() {
    let r = Rules::new();
    let http = r.db.probe("http-get").unwrap();
    let banner = r.db.probe("banner").unwrap();
    for (probe, response) in [
        (banner, &b"SSH-"[..]),
        (banner, b"220"),
        (banner, b"RFB 3.8\n"),
        (banner, b"+PONG\r\n"),
        (http, b"HTTP/2 200\r\n"),
        (http, b"<html>HTTP/1.1 200 OK</html>"),
        (http, b""),
    ] {
        if let Some(m) = r.db.identify(probe, response) {
            panic!(
                "{:?} matched rule at line {}",
                crate::escape(response, 60),
                m.rule.line
            );
        }
    }
    // Apache-Coyote must not be read as Apache httpd with junk.
    let m =
        r.db.identify(
            http,
            b"HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n",
        )
        .unwrap();
    assert_eq!(m.service.product.as_deref(), Some("Apache Tomcat Coyote"));
}

#[test]
fn detected_products_have_cpes() {
    // Every product a rule can name literally is either in the CPE table or
    // deliberately has none.
    let without_cpe = [
        "Apache Tomcat Coyote",
        "Microsoft HTTPAPI httpd",
        "Microsoft DNS",      // reports the Windows build
        "Cisco IOS",          // an OS, and the table makes application CPEs
        "Knot DNS",           // NVD naming not confirmed yet
        "Zebra print server", // NVD only has per-model printer firmware CPEs
        "$1",                 // products taken from the response itself
    ];
    let known: BTreeSet<&str> = crate::cpe::known_products().collect();
    let db = Database::parse(crate::db::BUILTIN).unwrap();
    for rule in db.rules() {
        let Some(p) = &rule.product else { continue };
        let name = p.source();
        assert!(
            known.contains(name) || without_cpe.contains(&name),
            "product {name:?} (probes.txt:{}) has no CPE mapping",
            rule.line
        );
    }
}
