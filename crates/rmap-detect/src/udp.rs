//! UDP requests and the code that reads their replies.
//!
//! Every payload is a minimal, well-formed request built from the
//! protocol's RFC or specification for rmap, not copied from another
//! scanner. The engine's UDP port scan sends [`udp_payload`] so services
//! answer at all; detection then sends the probes in `probes.txt`, whose
//! `@name` payloads are built here.
//!
//! Binary replies (DNS, NTP, SNMP, NetBIOS) are decoded in code by
//! [`decoder`]. A decoder checks the reply really answers our request and
//! returns a [`Decoded`]: a base [`Service`], plus any free text the
//! service disclosed (a `version.bind` string, an SNMP sysDescr, NTP
//! system variables), which the probe's match rules then read to name the
//! product. Every read is bounds-checked: malformed input gives `None`.

use rmap_core::{DetectMethod, Service};

use crate::db::Builtin;
use crate::der;
use crate::escape;

/// Transaction ID in our DNS, mDNS and NetBIOS requests ("rm").
const TXID: u16 = 0x726d;
/// Most bytes of disclosed text shown in `info`.
const MAX_TEXT: usize = 100;
/// Most mDNS service types listed.
const MAX_SERVICES: usize = 8;

/// The datagram the UDP port scan sends to `port`, so that services that
/// ignore an empty datagram answer. Unknown ports get an empty datagram.
pub fn udp_payload(port: u16) -> Vec<u8> {
    match port {
        53 | 5353 => dns_root_ns(),
        123 => ntp_client(),
        137 => netbios_status(),
        161 => snmp_get(SNMP_V1),
        1900 => ssdp_search(),
        _ => Vec::new(),
    }
}

/// A reply decoded in code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub service: Service,
    /// Text for the probe's match rules, e.g. a `version.bind` string.
    pub text: Option<Vec<u8>>,
}

/// Reads one reply; `None` if it is not an answer to our request.
pub type Decoder = fn(&[u8]) -> Option<Decoded>;

/// The decoder for replies to `b`, if `b` is a UDP payload decoded in code.
pub fn decoder(b: Builtin) -> Option<Decoder> {
    Some(match b {
        Builtin::DnsVersionBind => dns_version_reply,
        Builtin::MdnsServices => mdns_reply,
        Builtin::NtpClient => ntp_client_reply,
        Builtin::NtpReadvar => ntp_readvar_reply,
        Builtin::SnmpV1 | Builtin::SnmpV2c => snmp_reply,
        Builtin::NetbiosStatus => netbios_reply,
        _ => return None,
    })
}

fn service(name: &str, info: String) -> Service {
    Service {
        name: name.to_string(),
        info: Some(info),
        method: DetectMethod::Probe,
        confidence: 8,
        ..Default::default()
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

// ------------------------------------------------------------------ DNS ---

/// DNS header: ID, flags, then question/answer/authority/additional counts.
fn dns_header(id: u16, flags: u16, questions: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&flags.to_be_bytes());
    q.extend_from_slice(&questions.to_be_bytes());
    q.extend_from_slice(&[0; 6]);
    q
}

fn push_name(q: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
}

/// DNS (RFC 1035): a recursive query for the root zone's NS records. Any
/// DNS server answers it, even if only to refuse.
pub fn dns_root_ns() -> Vec<u8> {
    let mut q = dns_header(TXID, 0x0100, 1); // standard query, recursion desired
    q.push(0); // the root name
    q.extend_from_slice(&2u16.to_be_bytes()); // type NS
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN
    q
}

/// `version.bind` TXT in class CHAOS: BIND, Unbound, dnsmasq, Knot and
/// PowerDNS report their version here unless configured not to.
pub fn dns_version_bind() -> Vec<u8> {
    let mut q = dns_header(TXID, 0, 1);
    push_name(&mut q, "version.bind");
    q.extend_from_slice(&16u16.to_be_bytes()); // type TXT
    q.extend_from_slice(&3u16.to_be_bytes()); // class CH
    q
}

/// mDNS / DNS-SD (RFC 6762, RFC 6763): list the service types on the host.
/// Sent from a port other than 5353, so responders answer by unicast with
/// our ID ("legacy unicast", RFC 6762 section 6.7).
pub fn mdns_services() -> Vec<u8> {
    let mut q = dns_header(TXID, 0, 1);
    push_name(&mut q, "_services._dns-sd._udp.local");
    q.extend_from_slice(&12u16.to_be_bytes()); // type PTR
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN
    q
}

/// A possibly compressed name at `pos`: the name, and the offset just past
/// it where it was written (not where a pointer led).
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut after = None;
    let (mut jumps, mut raw_len) = (0, 0);
    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xc0 {
            0 if len == 0 => return Some((name, after.unwrap_or(pos + 1))),
            0 => {
                let label = msg.get(pos + 1..pos + 1 + len)?;
                raw_len += len + 1;
                if raw_len > 255 {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&escape(label, 63));
                pos += 1 + len;
            }
            0xc0 => {
                after.get_or_insert(pos + 2);
                jumps += 1;
                // Pointer loops would otherwise never end.
                if jumps > 16 {
                    return None;
                }
                pos = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            }
            _ => return None,
        }
    }
}

/// One resource record: its type and where its data sits in the message.
struct Record {
    kind: u16,
    data: std::ops::Range<usize>,
}

/// A DNS reply to our query `id`: its rcode and answer records.
fn dns_reply(msg: &[u8], ids: &[u16]) -> Option<(u16, Vec<Record>)> {
    let flags = u16_at(msg, 2)?;
    if !ids.contains(&u16_at(msg, 0)?) || flags & 0x8000 == 0 {
        return None;
    }
    let (questions, answers) = (u16_at(msg, 4)?, u16_at(msg, 6)?);
    let mut pos = 12;
    for _ in 0..questions {
        pos = read_name(msg, pos)?.1 + 4;
    }
    let mut records = Vec::new();
    // Each record takes at least 11 bytes, so the message length bounds
    // this loop; the cap bounds the work on a large reply.
    for _ in 0..answers.min(64) {
        let Some((_, at)) = read_name(msg, pos) else {
            break;
        };
        let (Some(kind), Some(len)) = (u16_at(msg, at), u16_at(msg, at + 8)) else {
            break;
        };
        let data = at + 10..at + 10 + len as usize;
        if data.end > msg.len() {
            break;
        }
        pos = data.end;
        records.push(Record { kind, data });
    }
    Some((flags & 0x000f, records))
}

fn rcode_name(rcode: u16) -> String {
    match rcode {
        0 => "no answer".into(),
        1 => "format error".into(),
        2 => "server failure".into(),
        3 => "name error".into(),
        4 => "not implemented".into(),
        5 => "refused".into(),
        n => format!("rcode {n}"),
    }
}

fn dns_version_reply(msg: &[u8]) -> Option<Decoded> {
    let (rcode, records) = dns_reply(msg, &[TXID])?;
    // TXT data is length-prefixed strings; the first holds the version.
    let txt = records.iter().filter(|r| r.kind == 16).find_map(|r| {
        let data = &msg[r.data.clone()];
        data.get(1..1 + *data.first()? as usize)
    });
    let info = match txt {
        Some(t) => format!("version.bind \"{}\"", escape(t, MAX_TEXT)),
        None => format!("version.bind not disclosed ({})", rcode_name(rcode)),
    };
    Some(Decoded {
        service: service("dns", info),
        text: txt.map(<[u8]>::to_vec),
    })
}

fn mdns_reply(msg: &[u8]) -> Option<Decoded> {
    // Responders should echo our ID; some send 0, the mDNS convention.
    let (_, records) = dns_reply(msg, &[TXID, 0])?;
    let mut types: Vec<String> = Vec::new();
    for r in records.iter().filter(|r| r.kind == 12) {
        let Some((name, _)) = read_name(msg, r.data.start) else {
            continue;
        };
        let name = name.trim_end_matches(".local").to_string();
        if !types.contains(&name) && types.len() < MAX_SERVICES {
            types.push(name);
        }
    }
    let info = if types.is_empty() {
        "no DNS-SD services listed".to_string()
    } else {
        format!("services: {}", types.join(", "))
    };
    Some(Decoded {
        service: service("mdns", info),
        text: None,
    })
}

// ------------------------------------------------------------------ NTP ---

/// NTP (RFC 5905): a version 4 client request. 48 bytes, all zero except
/// the first: leap indicator 3 (unsynchronised), version 4, mode 3 (client).
pub fn ntp_client() -> Vec<u8> {
    let mut p = vec![0; 48];
    p[0] = (3 << 6) | (4 << 3) | 3;
    p
}

/// NTP control message (mode 6, RFC 1305 appendix B / RFC 9327): read the
/// system variables, which ntpd answers with its version and OS unless
/// `restrict ... noquery` is set. 12-byte header, no data.
pub fn ntp_readvar() -> Vec<u8> {
    let mut p = vec![0; 12];
    p[0] = (2 << 3) | 6; // version 2, mode 6
    p[1] = 2; // opcode: read variables
    p[2..4].copy_from_slice(&1u16.to_be_bytes()); // sequence
    p
}

fn ntp_client_reply(r: &[u8]) -> Option<Decoded> {
    let (version, mode, stratum) = ((r.first()? >> 3) & 7, r[0] & 7, *r.get(1)?);
    if r.len() < 48 || mode != 4 || !(1..=4).contains(&version) {
        return None;
    }
    let refid = &r[12..16];
    let ascii = || escape(refid.split(|&b| b == 0).next().unwrap_or(&[]), 4);
    let info = match stratum {
        0 => format!("NTPv{version}, kiss code {}", ascii()),
        1 => format!("NTPv{version}, stratum 1, reference {}", ascii()),
        2..=15 if version == 4 || version == 3 => format!(
            "NTPv{version}, stratum {stratum}, reference {}.{}.{}.{}",
            refid[0], refid[1], refid[2], refid[3]
        ),
        _ => format!("NTPv{version}, unsynchronised"),
    };
    Some(Decoded {
        service: service("ntp", info),
        text: None,
    })
}

fn ntp_readvar_reply(r: &[u8]) -> Option<Decoded> {
    let (mode, op) = (*r.first()? & 7, *r.get(1)?);
    // Response bit set, opcode 2.
    if r.len() < 12 || mode != 6 || op & 0x80 == 0 || op & 0x1f != 2 {
        return None;
    }
    let count = u16_at(r, 10)? as usize;
    // Only the first fragment is read; the version comes first.
    let data = &r[12..r.len().min(12 + count)];
    let info = if op & 0x40 != 0 {
        "mode 6 control query refused".to_string()
    } else {
        "mode 6 control queries answered".to_string()
    };
    Some(Decoded {
        service: service("ntp", info),
        text: (!data.is_empty() && op & 0x40 == 0).then(|| data.to_vec()),
    })
}

// ----------------------------------------------------------------- SNMP ---

const SNMP_V1: u8 = 0;
const SNMP_V2C: u8 = 1;
const COMMUNITY: &[u8] = b"public";

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    // Short-form BER: every length we build is under 128.
    let mut v = vec![tag, content.len() as u8];
    v.extend_from_slice(content);
    v
}

/// SNMP v1 (RFC 1157) or v2c (RFC 1901, RFC 3416): a GetRequest for
/// sysDescr.0 with community "public".
pub fn snmp_get(version: u8) -> Vec<u8> {
    let sys_descr = tlv(0x06, &[0x2b, 6, 1, 2, 1, 1, 1, 0]); // 1.3.6.1.2.1.1.1.0
    let varbind = tlv(0x30, &[sys_descr, vec![0x05, 0x00]].concat()); // value NULL
    let pdu = tlv(
        0xa0, // GetRequest
        &[
            tlv(0x02, &[0x72]), // request ID
            tlv(0x02, &[0]),    // error status
            tlv(0x02, &[0]),    // error index
            tlv(0x30, &varbind),
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[tlv(0x02, &[version]), tlv(0x04, COMMUNITY), pdu].concat(),
    )
}

pub fn snmp_v1_get() -> Vec<u8> {
    snmp_get(SNMP_V1)
}

pub fn snmp_v2c_get() -> Vec<u8> {
    snmp_get(SNMP_V2C)
}

fn snmp_reply(r: &[u8]) -> Option<Decoded> {
    let (msg, _) = der::read(r)?;
    let mut fields = der::children(msg.content);
    let (version, community, pdu) = (fields.next()?, fields.next()?, fields.next()?);
    // GetResponse.
    if msg.tag != 0x30 || version.tag != 0x02 || community.tag != 0x04 || pdu.tag != 0xa2 {
        return None;
    }
    let label = match version.content {
        [0] => "SNMPv1",
        [1] => "SNMPv2c",
        _ => return None,
    };
    let mut pdu = der::children(pdu.content);
    let (_id, status) = (pdu.next()?, pdu.next()?);
    let value = pdu
        .nth(1)
        .and_then(|list| der::children(list.content).next())
        .and_then(|bind| der::children(bind.content).nth(1))
        .filter(|v| v.tag == 0x04)
        .map(|v| v.content);
    let mut info = format!(
        "{label}, community \"{}\" accepted",
        escape(community.content, 32)
    );
    if status.content.iter().any(|&b| b != 0) {
        info.push_str(", error response");
    }
    if let Some(text) = value {
        info.push_str(&format!(": {}", escape(text, MAX_TEXT)));
    }
    Some(Decoded {
        service: service("snmp", info),
        text: value.map(<[u8]>::to_vec),
    })
}

// -------------------------------------------------------------- NetBIOS ---

/// NetBIOS name service (RFC 1002): a node status request for the wildcard
/// name `*`, which Windows and Samba hosts answer with their name table.
pub fn netbios_status() -> Vec<u8> {
    let mut p = dns_header(TXID, 0, 1);
    // First-level encoding: each nibble of the 16-byte name becomes 'A'+n.
    let mut name = [0u8; 16];
    name[0] = b'*';
    p.push(32);
    for b in name {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0x0f));
    }
    p.push(0);
    p.extend_from_slice(&0x0021u16.to_be_bytes()); // type NBSTAT
    p.extend_from_slice(&1u16.to_be_bytes()); // class IN
    p
}

fn netbios_reply(r: &[u8]) -> Option<Decoded> {
    let (_, records) = dns_reply(r, &[TXID])?;
    let data = &r[records.iter().find(|rec| rec.kind == 0x21)?.data.clone()];
    let count = *data.first()? as usize;
    let table = data.get(1..1 + count * 18)?;
    let (mut host, mut group) = (None, None);
    for entry in table.as_chunks::<18>().0 {
        // 15-byte name, suffix byte (0x00 = workstation), flags (0x8000 = group).
        let name = escape(entry[..15].trim_ascii_end(), 15);
        if entry[15] != 0 || name.is_empty() {
            continue;
        }
        let slot = if entry[16] & 0x80 != 0 {
            &mut group
        } else {
            &mut host
        };
        slot.get_or_insert(name);
    }
    let mut parts = Vec::new();
    if let Some(h) = host {
        parts.push(format!("name {h}"));
    }
    if let Some(g) = group {
        parts.push(format!("workgroup {g}"));
    }
    // The statistics block starts with the adapter's MAC address.
    if let Some(mac) = data.get(1 + count * 18..1 + count * 18 + 6)
        && mac.iter().any(|&b| b != 0)
    {
        let hex: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
        parts.push(format!("MAC {}", hex.join(":")));
    }
    if parts.is_empty() {
        parts.push("empty name table".into());
    }
    Some(Decoded {
        service: service("netbios-ns", parts.join(", ")),
        text: None,
    })
}

// ----------------------------------------------------------------- SSDP ---

/// SSDP (UPnP Device Architecture 2.0): search for all devices and
/// services. Devices answer a unicast search directly; the reply is
/// HTTP-like text, read by match rules.
pub fn ssdp_search() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\n\
      HOST: 239.255.255.250:1900\r\n\
      MAN: \"ssdp:discover\"\r\n\
      MX: 1\r\n\
      ST: ssdp:all\r\n\r\n"
        .to_vec()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A DNS reply to `query` (our ID, its question echoed) with `answers`
    /// as `(type, rdata)`, each owner name a pointer to the question.
    pub fn dns_answer(query: &[u8], rcode: u8, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] |= 0x80; // QR
        r[3] = (r[3] & 0xf0) | rcode;
        r[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (kind, data) in answers {
            r.extend_from_slice(&[0xc0, 12]);
            r.extend_from_slice(&kind.to_be_bytes());
            r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            r.extend_from_slice(&(data.len() as u16).to_be_bytes());
            r.extend_from_slice(data);
        }
        r
    }

    pub fn txt(s: &str) -> Vec<u8> {
        let mut v = vec![s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    /// An SNMP GetResponse carrying `descr` as sysDescr.0.
    pub fn snmp_response(version: u8, descr: &[u8]) -> Vec<u8> {
        let oid = tlv(0x06, &[0x2b, 6, 1, 2, 1, 1, 1, 0]);
        let value = if descr.len() < 128 {
            tlv(0x04, descr)
        } else {
            let mut v = vec![0x04, 0x81, descr.len() as u8];
            v.extend_from_slice(descr);
            v
        };
        let bind = [oid, value].concat();
        let bind = long_tlv(0x30, &bind);
        let list = long_tlv(0x30, &bind);
        let pdu = long_tlv(
            0xa2,
            &[tlv(0x02, &[0x72]), tlv(0x02, &[0]), tlv(0x02, &[0]), list].concat(),
        );
        long_tlv(
            0x30,
            &[tlv(0x02, &[version]), tlv(0x04, COMMUNITY), pdu].concat(),
        )
    }

    fn long_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if content.len() < 128 {
            v.push(content.len() as u8);
        } else {
            v.push(0x82);
            v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(content);
        v
    }

    /// A NetBIOS node status reply listing `names` as (name, suffix, group).
    pub fn netbios_response(names: &[(&str, u8, bool)], mac: [u8; 6]) -> Vec<u8> {
        let mut data = vec![names.len() as u8];
        for (name, suffix, group) in names {
            let mut n = [b' '; 15];
            n[..name.len()].copy_from_slice(name.as_bytes());
            data.extend_from_slice(&n);
            data.push(*suffix);
            data.extend_from_slice(&[if *group { 0x84 } else { 0x04 }, 0]);
        }
        data.extend_from_slice(&mac);
        data.extend_from_slice(&[0; 40]);
        let q = netbios_status();
        let mut r = q[..12].to_vec();
        r[2] = 0x84; // response, authoritative
        r[4..8].copy_from_slice(&[0, 0, 0, 1]); // no question, one answer
        r.extend_from_slice(&q[12..12 + 34]); // the encoded name
        r.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0]);
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(&data);
        r
    }

    pub fn ntp_server(stratum: u8, refid: [u8; 4]) -> Vec<u8> {
        let mut r = vec![0; 48];
        r[0] = (4 << 3) | 4;
        r[1] = stratum;
        r[12..16].copy_from_slice(&refid);
        r
    }

    pub fn ntp_vars(text: &str) -> Vec<u8> {
        let mut r = vec![(2 << 3) | 6, 0x82, 0, 1, 0x06, 0x15, 0, 0, 0, 0];
        r.extend_from_slice(&(text.len() as u16).to_be_bytes());
        r.extend_from_slice(text.as_bytes());
        r
    }

    #[test]
    fn dns_queries_are_well_formed() {
        let q = udp_payload(53);
        assert_eq!(q.len(), 17);
        assert_eq!(&q[4..6], &[0, 1], "one question");
        assert_eq!(&q[12..], &[0, 0, 2, 0, 1]);
        assert_eq!(udp_payload(5353), q);
        let v = dns_version_bind();
        assert_eq!(&v[12..], b"\x07version\x04bind\x00\x00\x10\x00\x03");
        let m = mdns_services();
        assert_eq!(read_name(&m, 12).unwrap().0, "_services._dns-sd._udp.local");
    }

    #[test]
    fn ntp_requests() {
        let p = udp_payload(123);
        assert_eq!(p.len(), 48);
        assert_eq!(p[0], 0xe3);
        assert!(p[1..].iter().all(|&b| b == 0));
        assert_eq!(ntp_readvar(), [0x16, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn netbios_encodes_the_wildcard_name() {
        let p = udp_payload(137);
        assert_eq!(p.len(), 50);
        assert_eq!(p[12], 32);
        assert_eq!(&p[13..15], b"CK", "'*' is 0x2a");
        assert!(p[15..45].iter().all(|&b| b == b'A'));
        assert_eq!(&p[45..], &[0, 0, 0x21, 0, 1]);
    }

    #[test]
    fn snmp_matches_hand_encoded_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x30, 0x26,                                     // message, 38 bytes
            0x02, 0x01, 0x00,                               // version 1
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community
            0xa0, 0x19,                                     // GetRequest, 25 bytes
            0x02, 0x01, 0x72, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0e, 0x30, 0x0c,                         // varbind list, varbind
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x05, 0x00,
        ];
        assert_eq!(udp_payload(161), expected);
        assert_eq!(snmp_v2c_get()[4], 1, "v2c is encoded as 1");
    }

    #[test]
    fn ssdp_is_an_msearch() {
        let p = String::from_utf8(udp_payload(1900)).unwrap();
        assert!(p.starts_with("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"));
        assert!(p.contains("\r\nMAN: \"ssdp:discover\"\r\n"));
        assert!(p.ends_with("ST: ssdp:all\r\n\r\n"));
    }

    #[test]
    fn unknown_ports_get_an_empty_datagram() {
        assert!(udp_payload(9).is_empty());
        assert!(udp_payload(0).is_empty());
        assert!(udp_payload(u16::MAX).is_empty());
    }

    #[test]
    fn decodes_version_bind() {
        let r = dns_answer(&dns_version_bind(), 0, &[(16, txt("dnsmasq-2.90"))]);
        let d = dns_version_reply(&r).unwrap();
        assert_eq!(d.service.name, "dns");
        assert_eq!(d.text.as_deref(), Some(&b"dnsmasq-2.90"[..]));
        assert_eq!(
            d.service.info.as_deref(),
            Some("version.bind \"dnsmasq-2.90\"")
        );
        let refused = dns_version_reply(&dns_answer(&dns_version_bind(), 5, &[])).unwrap();
        assert_eq!(refused.text, None);
        assert_eq!(
            refused.service.info.as_deref(),
            Some("version.bind not disclosed (refused)")
        );
        // Our own query (no QR bit) or another ID is not an answer.
        assert!(dns_version_reply(&dns_version_bind()).is_none());
        let mut other = r.clone();
        other[0] = 0;
        assert!(dns_version_reply(&other).is_none());
    }

    #[test]
    fn decodes_mdns_service_list() {
        let ptr = |s: &str| {
            let mut v = Vec::new();
            push_name(&mut v, s);
            v
        };
        let r = dns_answer(
            &mdns_services(),
            0,
            &[
                (12, ptr("_http._tcp.local")),
                (12, ptr("_ssh._tcp.local")),
                (12, ptr("_http._tcp.local")),
                (12, vec![0xc0, 12]), // pointer to the question name
            ],
        );
        let d = mdns_reply(&r).unwrap();
        assert_eq!(
            d.service.info.as_deref(),
            Some("services: _http._tcp, _ssh._tcp, _services._dns-sd._udp")
        );
    }

    #[test]
    fn name_pointer_loops_end() {
        let mut r = dns_answer(&dns_version_bind(), 0, &[]);
        r.truncate(12);
        r[4..6].copy_from_slice(&[0, 1]);
        r.extend_from_slice(&[0xc0, 12]); // points at itself
        assert!(read_name(&r, 12).is_none());
        assert!(dns_version_reply(&r).is_none());
    }

    #[test]
    fn decodes_ntp() {
        let d = ntp_client_reply(&ntp_server(2, [192, 0, 2, 1])).unwrap();
        assert_eq!(
            d.service.info.as_deref(),
            Some("NTPv4, stratum 2, reference 192.0.2.1")
        );
        let d = ntp_client_reply(&ntp_server(1, *b"GPS\0")).unwrap();
        assert_eq!(
            d.service.info.as_deref(),
            Some("NTPv4, stratum 1, reference GPS")
        );
        let d = ntp_client_reply(&ntp_server(0, *b"RATE")).unwrap();
        assert_eq!(d.service.info.as_deref(), Some("NTPv4, kiss code RATE"));
        // Our own client request is not a server reply.
        assert!(ntp_client_reply(&ntp_client()).is_none());
        assert!(ntp_client_reply(&ntp_server(2, [0; 4])[..47]).is_none());

        let d = ntp_readvar_reply(&ntp_vars("version=\"ntpd 4.2.8p15\"")).unwrap();
        assert_eq!(d.text.as_deref(), Some(&b"version=\"ntpd 4.2.8p15\""[..]));
        // A count longer than the datagram is clamped.
        let mut short = ntp_vars("abc");
        short[11] = 200;
        assert_eq!(ntp_readvar_reply(&short).unwrap().text.unwrap(), b"abc");
        assert!(
            ntp_readvar_reply(&ntp_readvar()).is_none(),
            "request, not response"
        );
    }

    #[test]
    fn decodes_snmp() {
        let d = snmp_reply(&snmp_response(1, b"Linux gw 5.15.0 #1 SMP x86_64")).unwrap();
        assert_eq!(
            d.service.info.as_deref(),
            Some("SNMPv2c, community \"public\" accepted: Linux gw 5.15.0 #1 SMP x86_64")
        );
        assert_eq!(d.text.unwrap(), b"Linux gw 5.15.0 #1 SMP x86_64");
        let long = vec![b'x'; 200];
        let d = snmp_reply(&snmp_response(0, &long)).unwrap();
        assert!(d.service.info.unwrap().starts_with("SNMPv1,"));
        assert_eq!(d.text.unwrap().len(), 200);
        assert!(
            snmp_reply(&snmp_v2c_get()).is_none(),
            "request, not response"
        );
    }

    #[test]
    fn decodes_netbios() {
        let r = netbios_response(
            &[
                ("FILESRV", 0x00, false),
                ("FILESRV", 0x20, false),
                ("WORKGROUP", 0x00, true),
                ("\x01\x02__MSBROWSE__\x02", 0x01, true),
            ],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        );
        let d = netbios_reply(&r).unwrap();
        assert_eq!(
            d.service.info.as_deref(),
            Some("name FILESRV, workgroup WORKGROUP, MAC 00:11:22:33:44:55")
        );
        let d = netbios_reply(&netbios_response(&[("SAMBA", 0, false)], [0; 6])).unwrap();
        assert_eq!(d.service.info.as_deref(), Some("name SAMBA"));
    }

    #[test]
    fn hostile_text_is_escaped() {
        let r = dns_answer(&dns_version_bind(), 0, &[(16, txt("\x1b[31mevil\x07"))]);
        let info = dns_version_reply(&r).unwrap().service.info.unwrap();
        assert!(!info.bytes().any(|b| b.is_ascii_control()), "{info}");
    }
}
