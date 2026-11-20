//! Reading a server's answer to our TLS ClientHello.
//!
//! Records are parsed far enough to find the ServerHello (negotiated
//! version) and the first certificate in the Certificate message. Because
//! the ClientHello offers TLS 1.2 at most, the certificate travels in the
//! clear. A server that only answers with an alert still counts as TLS.

use rmap_core::CertInfo;
use rmap_core::sha256;

use crate::der;

const HANDSHAKE: u8 = 0x16;
const ALERT: u8 = 0x15;
/// Alert sent when the server won't speak the version the client offered.
pub const PROTOCOL_VERSION: u8 = 70;
/// Largest record allowed by the spec (2^14 plus expansion).
const MAX_RECORD: usize = 18_432;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsInfo {
    /// `TLSv1.2` etc., from the ServerHello.
    pub version: Option<&'static str>,
    /// Alert description code, if the server sent an alert.
    pub alert: Option<u8>,
    pub cert: Option<CertInfo>,
    /// `tls-cert SHA256:<hex>` of the leaf certificate's DER, when it
    /// arrived whole.
    pub fingerprint: Option<String>,
    /// This answered a TLS 1.0 retry after the TLS 1.2 ClientHello got
    /// `protocol_version`.
    pub legacy_retry: bool,
}

impl TlsInfo {
    /// One compact line for `Service::info`.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        parts.push(self.version.unwrap_or("TLS").to_string());
        if self.legacy_retry {
            parts.push(match self.version {
                Some("TLSv1.0") => "accepts TLS 1.0 only".to_string(),
                v => format!("accepts {} after refusing TLS 1.2", v.unwrap_or("TLS")),
            });
        } else if self.refused_version() {
            parts.push("refused TLS 1.2 ClientHello (protocol_version)".into());
        } else if let Some(a) = self.alert {
            parts.push(format!("alert {}", alert_name(a)));
        }
        if let Some(c) = &self.cert {
            if let Some(cn) = &c.subject_cn {
                parts.push(format!("CN={cn}"));
            }
            let sans: Vec<&str> = c
                .sans
                .iter()
                .map(String::as_str)
                .filter(|s| Some(*s) != c.subject_cn.as_deref())
                .collect();
            if !sans.is_empty() {
                let shown = sans.iter().take(3).copied().collect::<Vec<_>>().join(",");
                let more = sans.len().saturating_sub(3);
                parts.push(if more > 0 {
                    format!("SAN={shown} +{more}")
                } else {
                    format!("SAN={shown}")
                });
            }
            if c.self_signed {
                parts.push("self-signed".into());
            } else if let Some(i) = &c.issuer_cn {
                parts.push(format!("issuer={i}"));
            }
            if let Some(d) = &c.not_after {
                parts.push(format!("expires {d}"));
            }
        }
        parts.join("; ")
    }

    /// The server turned down the TLS 1.2 ClientHello's version.
    pub fn refused_version(&self) -> bool {
        self.version.is_none() && self.alert == Some(PROTOCOL_VERSION)
    }
}

fn version_name(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0300 => "SSLv3",
        0x0301 => "TLSv1.0",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2",
        0x0304 => "TLSv1.3",
        _ => return None,
    })
}

fn alert_name(code: u8) -> String {
    match code {
        40 => "handshake_failure".into(),
        PROTOCOL_VERSION => "protocol_version".into(),
        71 => "insufficient_security".into(),
        80 => "internal_error".into(),
        112 => "unrecognized_name".into(),
        n => n.to_string(),
    }
}

/// `None` unless the response starts with a well-formed TLS record.
pub fn analyze(response: &[u8]) -> Option<TlsInfo> {
    let mut info = TlsInfo::default();
    let mut handshake = Vec::new();
    let mut rest = response;
    let mut records = 0;
    while rest.len() >= 5 {
        let kind = rest[0];
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let plausible =
            matches!(kind, 0x14..=0x17) && rest[1] == 3 && rest[2] <= 4 && len <= MAX_RECORD;
        if !plausible {
            break;
        }
        // A truncated final record still gives us what arrived.
        let body = &rest[5..(5 + len).min(rest.len())];
        match kind {
            HANDSHAKE => handshake.extend_from_slice(body),
            ALERT if body.len() >= 2 && info.alert.is_none() => info.alert = Some(body[1]),
            _ => {}
        }
        records += 1;
        rest = &rest[(5 + len).min(rest.len())..];
    }
    if records == 0 {
        return None;
    }
    parse_handshake(&handshake, &mut info);
    if info.version.is_none() && info.alert.is_none() {
        // Records with nothing we understand: probably not TLS after all.
        return None;
    }
    Some(info)
}

fn parse_handshake(mut buf: &[u8], info: &mut TlsInfo) {
    while buf.len() >= 4 {
        let kind = buf[0];
        let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        let body = &buf[4..(4 + len).min(buf.len())];
        match kind {
            2 => info.version = server_hello_version(body),
            11 => {
                let leaf = first_certificate(body);
                info.cert = leaf.and_then(der::certificate);
                // Hash only a whole DER element, never a truncated one.
                info.fingerprint = leaf.and_then(der::read).map(|(t, _)| {
                    format!("tls-cert SHA256:{}", sha256::hex(&sha256::digest(t.raw)))
                });
            }
            _ => {}
        }
        if 4 + len > buf.len() {
            break;
        }
        buf = &buf[4 + len..];
    }
}

fn server_hello_version(body: &[u8]) -> Option<&'static str> {
    let legacy = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
    // version(2) random(32) session_id(1+n) cipher(2) compression(1) exts
    let sid_len = *body.get(34)? as usize;
    let mut at = 35 + sid_len + 3;
    let ext_len = body
        .get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize);
    if let Some(ext_len) = ext_len {
        at += 2;
        let exts = body.get(at..(at + ext_len).min(body.len())).unwrap_or(&[]);
        let mut e = exts;
        while e.len() >= 4 {
            let kind = u16::from_be_bytes([e[0], e[1]]);
            let len = u16::from_be_bytes([e[2], e[3]]) as usize;
            if kind == 0x002b && len == 2 && e.len() >= 6 {
                return version_name(u16::from_be_bytes([e[4], e[5]]));
            }
            e = e.get(4 + len..).unwrap_or(&[]);
        }
    }
    version_name(legacy)
}

fn first_certificate(body: &[u8]) -> Option<&[u8]> {
    // certificate_list length(3), then each cert: length(3) + DER.
    let len = u32::from_be_bytes([0, *body.get(3)?, *body.get(4)?, *body.get(5)?]) as usize;
    let end = (6 + len).min(body.len());
    body.get(6..end)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::der::tests::fake_cert;

    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![kind, 3, 3];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut h = vec![kind];
        h.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        h.extend_from_slice(body);
        h
    }

    /// What a TLS 1.2 server sends back: ServerHello, Certificate and
    /// ServerHelloDone, the first two in one record.
    pub fn server_flight(cert: &[u8]) -> Vec<u8> {
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0xc0, 0x2f, 0]); // cipher, compression
        hello.extend_from_slice(&[0, 5, 0xff, 0x01, 0, 1, 0]); // renegotiation_info
        let mut certs = (cert.len() as u32).to_be_bytes()[1..].to_vec();
        certs.extend_from_slice(cert);
        let mut list = (certs.len() as u32).to_be_bytes()[1..].to_vec();
        list.extend_from_slice(&certs);
        let mut first = handshake(2, &hello);
        first.extend(handshake(11, &list));
        let mut out = record(HANDSHAKE, &first);
        out.extend(record(HANDSHAKE, &handshake(14, &[])));
        out
    }

    #[test]
    fn reads_version_and_certificate() {
        let cert = fake_cert(
            "db.example.test",
            "Example CA",
            &["db.example.test", "db2.example.test"],
        );
        let info = analyze(&server_flight(&cert)).unwrap();
        assert_eq!(info.version, Some("TLSv1.2"));
        let c = info.cert.as_ref().unwrap();
        assert_eq!(c.subject_cn.as_deref(), Some("db.example.test"));
        assert_eq!(
            info.summary(),
            "TLSv1.2; CN=db.example.test; SAN=db2.example.test; issuer=Example CA; expires 2035-06-30"
        );
    }

    #[test]
    fn alert_only_is_still_tls() {
        let info = analyze(&record(ALERT, &[2, 40])).unwrap();
        assert_eq!(info.alert, Some(40));
        assert_eq!(info.summary(), "TLS; alert handshake_failure");
    }

    #[test]
    fn protocol_version_alert_names_the_refused_version() {
        let info = analyze(&record(ALERT, &[2, 70])).unwrap();
        assert!(info.refused_version());
        assert_eq!(
            info.summary(),
            "TLS; refused TLS 1.2 ClientHello (protocol_version)"
        );
        let mut retried = info.clone();
        retried.version = Some("TLSv1.0");
        retried.legacy_retry = true;
        assert_eq!(retried.summary(), "TLSv1.0; accepts TLS 1.0 only");
    }

    #[test]
    fn leaf_fingerprint_and_cert_info() {
        let cert = fake_cert("nas.example.test", "nas.example.test", &[]);
        let info = analyze(&server_flight(&cert)).unwrap();
        let want = format!("tls-cert SHA256:{}", sha256::hex(&sha256::digest(&cert)));
        assert_eq!(info.fingerprint.as_deref(), Some(want.as_str()));
        let c = info.cert.unwrap();
        assert_eq!(c.not_before.as_deref(), Some("2024-01-01"));
        assert!(c.self_signed);
        // A truncated certificate gets names but no fingerprint.
        let flight = server_flight(&cert);
        let cut = analyze(&flight[..flight.len() - 30]).unwrap();
        assert_eq!(cut.fingerprint, None);
    }

    #[test]
    fn not_tls() {
        for r in [
            &b"HTTP/1.1 400 Bad Request\r\n"[..],
            b"SSH-2.0-x\r\n",
            b"",
            b"\x16\x03",
        ] {
            assert_eq!(analyze(r), None, "{r:?}");
        }
        assert_eq!(analyze(&record(0x17, b"data")), None);
    }

    #[test]
    fn truncated_flights_never_panic() {
        let flight = server_flight(&fake_cert("x", "y", &["z"]));
        for n in 0..flight.len() {
            let _ = analyze(&flight[..n]);
        }
    }

    #[test]
    fn tls13_supported_versions_wins() {
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x13, 0x01, 0]);
        hello.extend_from_slice(&[0, 6, 0, 0x2b, 0, 2, 3, 4]);
        let info = analyze(&record(HANDSHAKE, &handshake(2, &hello))).unwrap();
        assert_eq!(info.version, Some("TLSv1.3"));
    }
}
