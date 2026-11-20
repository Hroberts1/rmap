//! Just enough DER to read names out of an X.509 certificate: the subject
//! and issuer common names, the DNS and IP subject alternative names, and
//! the validity dates. Every read is bounds-checked; malformed input gives
//! `None` or partial results, never a panic.

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// Most alternative names kept.
pub const MAX_SANS: usize = 16;
/// Longest name kept, in bytes.
const MAX_NAME: usize = 255;

/// One tag-length-value element.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The whole element, header included.
    pub raw: &'a [u8],
}

/// Read one element from the front of `input`, returning it and the rest.
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *input.first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags never appear in what we read
    }
    let first = *input.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = input.get(2..2 + n)?;
        let len = bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    let content = input.get(header..end)?;
    Some((
        Tlv {
            tag,
            content,
            raw: &input[..end],
        },
        &input[end..],
    ))
}

/// Iterate over the elements inside a constructed value.
pub fn children(mut content: &[u8]) -> impl Iterator<Item = Tlv<'_>> {
    std::iter::from_fn(move || {
        let (tlv, rest) = read(content)?;
        content = rest;
        Some(tlv)
    })
}

fn expect(input: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    let (tlv, rest) = read(input)?;
    (tlv.tag == tag).then_some((tlv, rest))
}

use rmap_core::CertInfo;

/// Pull names and dates out of a DER-encoded certificate.
pub fn certificate(der: &[u8]) -> Option<CertInfo> {
    let (cert, _) = expect(der, SEQUENCE)?;
    let (tbs, _) = expect(cert.content, SEQUENCE)?;
    let mut rest = tbs.content;
    // Optional explicit version [0].
    if let Some((v, after)) = read(rest)
        && v.tag == 0xa0
    {
        rest = after;
    }
    let (_serial, rest) = expect(rest, 0x02)?;
    let (_sig_alg, rest) = expect(rest, SEQUENCE)?;
    let (issuer, rest) = expect(rest, SEQUENCE)?;
    let (validity, rest) = expect(rest, SEQUENCE)?;
    let mut names = CertInfo {
        issuer_cn: common_name(issuer.content),
        ..Default::default()
    };
    let mut dates = children(validity.content);
    names.not_before = dates.next().and_then(time);
    names.not_after = dates.next().and_then(time);
    let Some((subject, rest)) = expect(rest, SEQUENCE) else {
        return Some(names);
    };
    names.subject_cn = common_name(subject.content);
    names.self_signed = subject.raw == issuer.raw;
    // Skip the public key and optional unique IDs, then find extensions [3].
    if let Some(ext) = children(rest).find(|t| t.tag == 0xa3) {
        names.sans = alt_names(ext.content);
    }
    Some(names)
}

fn common_name(name: &[u8]) -> Option<String> {
    for rdn in children(name).filter(|t| t.tag == SET) {
        for atv in children(rdn.content).filter(|t| t.tag == SEQUENCE) {
            let mut parts = children(atv.content);
            let (Some(oid), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            if oid.tag == OID && oid.content == OID_CN {
                return text(value.content);
            }
        }
    }
    None
}

fn alt_names(extensions: &[u8]) -> Vec<String> {
    let Some((list, _)) = expect(extensions, SEQUENCE) else {
        return Vec::new();
    };
    for ext in children(list.content).filter(|t| t.tag == SEQUENCE) {
        let mut parts = children(ext.content);
        let Some(oid) = parts.next() else { continue };
        if oid.tag != OID || oid.content != OID_SAN {
            continue;
        }
        // Skip the optional `critical` boolean.
        let Some(value) = parts.find(|t| t.tag == OCTET_STRING) else {
            return Vec::new();
        };
        let Some((names, _)) = expect(value.content, SEQUENCE) else {
            return Vec::new();
        };
        return children(names.content)
            .filter_map(|g| match g.tag {
                0x82 => text(g.content), // dNSName
                0x87 => ip(g.content),   // iPAddress
                _ => None,
            })
            .take(MAX_SANS)
            .collect();
    }
    Vec::new()
}

/// Printable text, or `None` if the bytes don't look like a name.
fn text(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_NAME)]);
    let s: String = s.chars().filter(|c| !c.is_control()).collect();
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn ip(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            Some(std::net::Ipv6Addr::from(a).to_string())
        }
        _ => None,
    }
}

fn time(t: Tlv<'_>) -> Option<String> {
    let s = std::str::from_utf8(t.content).ok()?;
    if !s.is_ascii() {
        return None;
    }
    let (year, rest) = match t.tag {
        UTC_TIME if s.len() >= 6 => {
            let yy: u32 = s.get(..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        GENERALIZED_TIME if s.len() >= 8 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let d = rest.get(r)?;
        d.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| d.parse().ok())?
    };
    let (month, day) = (digits(0..2)?, digits(2..4)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// DER element with a correctly encoded length.
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = content.len();
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.extend_from_slice(&[0x81, n as u8]);
        } else {
            out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(content);
        out
    }

    fn name(cn: &str) -> Vec<u8> {
        let mut atv = tlv(OID, OID_CN);
        atv.extend(tlv(0x0c, cn.as_bytes()));
        tlv(SEQUENCE, &tlv(SET, &tlv(SEQUENCE, &atv)))
    }

    /// A structurally valid certificate with made-up keys and signature.
    pub fn fake_cert(subject: &str, issuer: &str, sans: &[&str]) -> Vec<u8> {
        let mut tbs = tlv(0xa0, &tlv(0x02, &[2]));
        tbs.extend(tlv(0x02, &[0x01, 0x23]));
        tbs.extend(tlv(SEQUENCE, &tlv(OID, &[0x2a, 0x86, 0x48])));
        tbs.extend(name(issuer));
        let mut validity = tlv(UTC_TIME, b"240101000000Z");
        validity.extend(tlv(GENERALIZED_TIME, b"20350630235959Z"));
        tbs.extend(tlv(SEQUENCE, &validity));
        tbs.extend(name(subject));
        tbs.extend(tlv(SEQUENCE, &tlv(0x03, &[0; 40])));
        let mut gn = Vec::new();
        for s in sans {
            match s.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(a)) => gn.extend(tlv(0x87, &a.octets())),
                Ok(std::net::IpAddr::V6(a)) => gn.extend(tlv(0x87, &a.octets())),
                Err(_) => gn.extend(tlv(0x82, s.as_bytes())),
            }
        }
        let mut ext = tlv(OID, OID_SAN);
        ext.extend(tlv(0x01, &[0xff]));
        ext.extend(tlv(OCTET_STRING, &tlv(SEQUENCE, &gn)));
        let mut other = tlv(OID, &[0x55, 0x1d, 0x13]);
        other.extend(tlv(OCTET_STRING, &tlv(SEQUENCE, &[])));
        let mut exts = tlv(SEQUENCE, &other);
        exts.extend(tlv(SEQUENCE, &ext));
        tbs.extend(tlv(0xa3, &tlv(SEQUENCE, &exts)));

        let mut cert = tlv(SEQUENCE, &tbs);
        cert.extend(tlv(SEQUENCE, &tlv(OID, &[0x2a, 0x86, 0x48])));
        cert.extend(tlv(0x03, &[0; 64]));
        tlv(SEQUENCE, &cert)
    }

    #[test]
    fn reads_names() {
        let der = fake_cert(
            "www.example.test",
            "Example CA",
            &["www.example.test", "10.0.0.1", "::1"],
        );
        let n = certificate(&der).unwrap();
        assert_eq!(n.subject_cn.as_deref(), Some("www.example.test"));
        assert_eq!(n.issuer_cn.as_deref(), Some("Example CA"));
        assert_eq!(n.sans, ["www.example.test", "10.0.0.1", "::1"]);
        assert_eq!(n.not_before.as_deref(), Some("2024-01-01"));
        assert_eq!(n.not_after.as_deref(), Some("2035-06-30"));
        assert!(!n.self_signed);
        assert!(certificate(&fake_cert("a", "a", &[])).unwrap().self_signed);
    }

    #[test]
    fn long_form_lengths() {
        let content = vec![0xab; 300];
        let enc = tlv(OCTET_STRING, &content);
        let (t, rest) = read(&enc).unwrap();
        assert_eq!((t.tag, t.content.len(), rest.len()), (OCTET_STRING, 300, 0));
        assert!(
            read(&[0x04, 0x85, 1, 1, 1, 1, 1]).is_none(),
            "5-byte length"
        );
        assert!(read(&[0x04, 0x80]).is_none(), "indefinite length");
        assert!(read(&[0x04, 0x82, 0xff, 0xff, 0]).is_none(), "overrun");
        assert!(read(&[0x1f, 0x01, 0x00]).is_none(), "multi-byte tag");
    }

    #[test]
    fn truncated_certificates_never_panic() {
        let der = fake_cert("host", "ca", &["a.test", "b.test"]);
        for n in 0..der.len() {
            let _ = certificate(&der[..n]);
        }
    }
}
