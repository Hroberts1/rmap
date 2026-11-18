//! Just enough of the DNS wire format (RFC 1035) for name lookups: build a
//! one-question query, and walk the answer records of a reply. NetBIOS
//! (RFC 1002) and mDNS (RFC 6762) share the format. Parsers never panic.

use std::net::IpAddr;
use std::ops::Range;

pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_NBSTAT: u16 = 0x21;
pub const CLASS_IN: u16 = 1;
/// mDNS: ask for a unicast reply (RFC 6762 section 5.4).
pub const CLASS_UNICAST: u16 = 0x8000;

const HEADER: usize = 12;
/// Compression pointers followed per name before giving up on a loop.
const MAX_JUMPS: usize = 32;

/// A query with one question. `qname` is a list of labels; each must be
/// 1..=63 bytes (callers build them, so this is not user input).
pub fn query(id: u16, recursion: bool, qname: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(HEADER + 64);
    q.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = if recursion { 0x0100 } else { 0 };
    q.extend_from_slice(&flags.to_be_bytes());
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
    for label in qname {
        debug_assert!((1..=63).contains(&label.len()));
        q.push(label.len() as u8);
        q.extend_from_slice(label);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&qclass.to_be_bytes());
    q
}

/// The reverse-lookup name for `ip`: `4.3.2.1.in-addr.arpa` or the
/// nibble form under `ip6.arpa`.
pub fn reverse_name(ip: IpAddr) -> Vec<String> {
    let mut labels: Vec<String> = match ip {
        IpAddr::V4(v4) => v4.octets().iter().rev().map(|o| o.to_string()).collect(),
        IpAddr::V6(v6) => v6
            .octets()
            .iter()
            .rev()
            .flat_map(|b| [b & 0x0f, b >> 4])
            .map(|n| format!("{n:x}"))
            .collect(),
    };
    match ip {
        IpAddr::V4(_) => labels.extend(["in-addr".into(), "arpa".into()]),
        IpAddr::V6(_) => labels.extend(["ip6".into(), "arpa".into()]),
    }
    labels
}

/// One answer record: its owner name, type, and where its data sits in
/// the message.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub owner: String,
    pub kind: u16,
    pub data: Range<usize>,
}

/// The answer records of a successful reply with id `id`, or `None` if
/// `msg` is not one (wrong id, a query, an error code, or malformed).
/// `id` of `None` accepts any id.
pub fn answers(msg: &[u8], id: Option<u16>) -> Option<Vec<Record>> {
    let header = msg.get(..HEADER)?;
    let got = u16::from_be_bytes([header[0], header[1]]);
    if id.is_some_and(|want| want != got) {
        return None;
    }
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None; // not a response, or an error code
    }
    let count = |i: usize| u16::from_be_bytes([header[i], header[i + 1]]) as usize;
    let (questions, answers) = (count(4), count(6));
    let mut pos = HEADER;
    for _ in 0..questions {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut out = Vec::with_capacity(answers.min(16));
    for _ in 0..answers {
        let (owner, end) = read_name(msg, pos)?;
        let fixed = msg.get(end..end + 10)?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let len = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let start = end + 10;
        if start + len > msg.len() {
            return None;
        }
        out.push(Record {
            owner,
            kind,
            data: start..start + len,
        });
        pos = start + len;
    }
    Some(out)
}

/// Position just past the name at `pos`, without decoding it.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xc0 == 0xc0 => {
                msg.get(pos + 1)?;
                return Some(pos + 2);
            }
            l if l & 0xc0 == 0 => pos += 1 + l as usize,
            _ => return None,
        }
    }
}

/// Decode the name at `pos`, following compression pointers. Returns the
/// dotted name (labels decoded as lossy UTF-8; callers clean it before
/// display) and the position just past it in the original message.
pub fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => {
                return Some((labels.join("."), end.unwrap_or(pos + 1)));
            }
            l if l & 0xc0 == 0xc0 => {
                let target = (usize::from(l & 0x3f) << 8) | usize::from(*msg.get(pos + 1)?);
                end.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                pos = target;
            }
            l if l & 0xc0 == 0 => {
                let label = msg.get(pos + 1..pos + 1 + l as usize)?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                pos += 1 + l as usize;
            }
            _ => return None,
        }
    }
}

/// The name a PTR lookup for `qname` points at, following CNAME records
/// (classless reverse delegation uses them). Names compare without case.
pub fn ptr_target(msg: &[u8], records: &[Record], qname: &str) -> Option<String> {
    let mut owner = qname.to_ascii_lowercase();
    // Each CNAME can move the owner on once; more than this is a loop.
    for _ in 0..8 {
        let mut moved = false;
        for r in records {
            if r.owner.to_ascii_lowercase() != owner {
                continue;
            }
            match r.kind {
                TYPE_PTR => return read_name(msg, r.data.start).map(|(n, _)| n),
                TYPE_CNAME => {
                    owner = read_name(msg, r.data.start)?.0.to_ascii_lowercase();
                    moved = true;
                    break;
                }
                _ => {}
            }
        }
        if !moved {
            return None;
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A reply to `q` (a query from `query`) with the given answers, each
    /// `(type, rdata)` and owned by the question name.
    pub fn reply(q: &[u8], answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] |= 0x80; // QR
        r[7] = answers.len() as u8;
        for (kind, data) in answers {
            r.extend_from_slice(&[0xc0, 12]); // owner: the question name
            r.extend_from_slice(&kind.to_be_bytes());
            r.extend_from_slice(&CLASS_IN.to_be_bytes());
            r.extend_from_slice(&60u32.to_be_bytes());
            r.extend_from_slice(&(data.len() as u16).to_be_bytes());
            r.extend_from_slice(data);
        }
        r
    }

    pub fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn labels(name: &[String]) -> Vec<&[u8]> {
        name.iter().map(|l| l.as_bytes()).collect()
    }

    #[test]
    fn reverse_names() {
        let v4 = reverse_name("192.0.2.10".parse().unwrap());
        assert_eq!(v4.join("."), "10.2.0.192.in-addr.arpa");
        let v6 = reverse_name("2001:db8::1".parse().unwrap());
        let v6 = v6.join(".");
        assert!(v6.starts_with("1.0.0.0.0.0.0.0"), "{v6}");
        assert!(v6.ends_with("8.b.d.0.1.0.0.2.ip6.arpa"), "{v6}");
        assert_eq!(v6.split('.').count(), 34);
    }

    #[test]
    fn ptr_round_trip() {
        let name = reverse_name("192.0.2.10".parse().unwrap());
        let q = query(0x1234, true, &labels(&name), TYPE_PTR, CLASS_IN);
        let r = reply(&q, &[(TYPE_PTR, encode_name("printer.corp.lan"))]);
        let recs = answers(&r, Some(0x1234)).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            ptr_target(&r, &recs, &name.join(".")).as_deref(),
            Some("printer.corp.lan")
        );
        // Wrong id, a query, and an error code are all rejected.
        assert!(answers(&r, Some(1)).is_none());
        assert!(answers(&q, Some(0x1234)).is_none());
        let mut nx = r.clone();
        nx[3] |= 3;
        assert!(answers(&nx, Some(0x1234)).is_none());
    }

    #[test]
    fn follows_cname_to_ptr() {
        let name = reverse_name("192.0.2.10".parse().unwrap());
        let q = query(7, true, &labels(&name), TYPE_PTR, CLASS_IN);
        let mut r = reply(
            &q,
            &[(TYPE_CNAME, encode_name("10.0-25.2.0.192.in-addr.arpa"))],
        );
        // A second answer owned by the CNAME target.
        r[7] = 2;
        r.extend_from_slice(&encode_name("10.0-25.2.0.192.in-addr.arpa"));
        let data = encode_name("nas.lan");
        r.extend_from_slice(&TYPE_PTR.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(&data);
        let recs = answers(&r, Some(7)).unwrap();
        assert_eq!(
            ptr_target(&r, &recs, &name.join(".")).as_deref(),
            Some("nas.lan")
        );
    }

    #[test]
    fn pointer_loops_and_truncation_end() {
        // A name that points at itself.
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xc0, 12]);
        assert!(read_name(&msg, 12).is_none());
        // Every truncation of a valid reply is rejected or parsed, never a panic.
        let name = reverse_name("192.0.2.10".parse().unwrap());
        let q = query(9, true, &labels(&name), TYPE_PTR, CLASS_IN);
        let r = reply(&q, &[(TYPE_PTR, encode_name("a.b"))]);
        for n in 0..r.len() {
            let _ = answers(&r[..n], Some(9));
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        // A small xorshift so the test is deterministic without a crate.
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..5000 {
            let len = (next() % 80) as usize;
            let mut msg: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if msg.len() > 3 {
                msg[2] |= 0x80;
                msg[3] &= 0xf0;
            }
            if let Some(recs) = answers(&msg, None) {
                let _ = ptr_target(&msg, &recs, "x");
            }
        }
    }
}
