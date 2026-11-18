//! UDP probe payloads, written for rmap.
//!
//! Many UDP services ignore an empty datagram, so a silent port could be
//! open or filtered. Sending a request the service understands makes an
//! open port answer. Each payload here is a minimal, well-formed request
//! built from the protocol's RFC, not copied from another scanner.

/// The payload to send to a UDP port. Ports without a known protocol get an
/// empty datagram.
pub fn udp_payload(port: u16) -> Vec<u8> {
    match port {
        53 | 5353 => dns_query(),
        123 => ntp_client(),
        137 => netbios_node_status(),
        161 => snmp_v1_get(),
        1900 => ssdp_search(),
        _ => Vec::new(),
    }
}

/// DNS (RFC 1035): a recursive query for the root zone's NS records. Any
/// DNS server answers it, even if only to refuse.
fn dns_query() -> Vec<u8> {
    let mut q = Vec::with_capacity(17);
    q.extend_from_slice(&0x726du16.to_be_bytes()); // transaction ID "rm"
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question, no other records
    q.push(0); // the root name
    q.extend_from_slice(&2u16.to_be_bytes()); // type NS
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN
    q
}

/// NTP (RFC 5905): a version 4 client request. 48 bytes, all zero except
/// the first: leap indicator 3 (unsynchronised), version 4, mode 3 (client).
fn ntp_client() -> Vec<u8> {
    let mut p = vec![0; 48];
    p[0] = (3 << 6) | (4 << 3) | 3;
    p
}

/// NetBIOS name service (RFC 1002): a node status request for the wildcard
/// name `*`, which Windows and Samba hosts answer with their name table.
fn netbios_node_status() -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&0x726du16.to_be_bytes()); // transaction ID
    p.extend_from_slice(&[0, 0]); // flags: query
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
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

/// SNMPv1 (RFC 1157): a GetRequest for sysDescr.0 with community "public".
fn snmp_v1_get() -> Vec<u8> {
    // Short-form BER: every length here is under 128.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }
    let sys_descr = tlv(0x06, &[0x2b, 6, 1, 2, 1, 1, 1, 0]); // 1.3.6.1.2.1.1.1.0
    let varbind = tlv(0x30, &[sys_descr, vec![0x05, 0x00]].concat()); // value NULL
    let varbinds = tlv(0x30, &varbind);
    let pdu = tlv(
        0xa0, // GetRequest
        &[
            tlv(0x02, &[0x72]), // request ID
            tlv(0x02, &[0]),    // error status
            tlv(0x02, &[0]),    // error index
            varbinds,
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[tlv(0x02, &[0]), tlv(0x04, b"public"), pdu].concat(), // version 1 is encoded as 0
    )
}

/// SSDP (UPnP Device Architecture): a search for all devices and services.
fn ssdp_search() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\n\
      HOST: 239.255.255.250:1900\r\n\
      MAN: \"ssdp:discover\"\r\n\
      MX: 1\r\n\
      ST: ssdp:all\r\n\r\n"
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_is_a_root_ns_query() {
        let q = udp_payload(53);
        assert_eq!(q.len(), 17);
        assert_eq!(&q[4..6], &[0, 1], "one question");
        assert_eq!(&q[12..], &[0, 0, 2, 0, 1]);
        assert_eq!(udp_payload(5353), q);
    }

    #[test]
    fn ntp_is_a_v4_client_request() {
        let p = udp_payload(123);
        assert_eq!(p.len(), 48);
        assert_eq!(p[0], 0xe3);
        assert!(p[1..].iter().all(|&b| b == 0));
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
}
