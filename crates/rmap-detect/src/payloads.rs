//! Probe payloads built in code, referenced from the database as `@name`.

use crate::db::Builtin;
use crate::udp;

pub fn build(b: Builtin) -> Vec<u8> {
    match b {
        Builtin::TlsClientHello => tls_client_hello(&random32()),
        Builtin::SmbNegotiate => smb_negotiate(),
        Builtin::MongoBuildInfo => mongodb_buildinfo(),
        Builtin::DnsVersionBind => udp::dns_version_bind(),
        Builtin::DnsVersionBindTcp => udp::dns_over_tcp(&udp::dns_version_bind()),
        Builtin::MdnsServices => udp::mdns_services(),
        Builtin::NtpReadvar => udp::ntp_readvar(),
        Builtin::NtpClient => udp::ntp_client(),
        Builtin::SnmpV2c => udp::snmp_v2c_get(),
        Builtin::SnmpV1 => udp::snmp_v1_get(),
        Builtin::NetbiosStatus => udp::netbios_status(),
        Builtin::SsdpSearch => udp::ssdp_search(),
    }
}

/// Not cryptographic: the ClientHello random only has to look plausible.
fn random32() -> [u8; 32] {
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
        | 1;
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out
}

fn u16be(v: usize) -> [u8; 2] {
    (v as u16).to_be_bytes()
}

fn u24be(v: usize) -> [u8; 3] {
    let b = (v as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

fn extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&u16be(body.len()));
    out.extend_from_slice(body);
}

/// A TLS 1.2 ClientHello. It deliberately offers nothing newer: TLS 1.3
/// encrypts the certificate, and reading it is the point. No SNI is sent
/// because the target is an address.
pub fn tls_client_hello(random: &[u8; 32]) -> Vec<u8> {
    client_hello(random, 0x03)
}

/// The same ClientHello offering TLS 1.0, for servers that refused 1.2.
pub fn tls10_client_hello() -> Vec<u8> {
    client_hello(&random32(), 0x01)
}

/// `minor` is the TLS 1.x version byte: 0x01 for 1.0, 0x03 for 1.2.
fn client_hello(random: &[u8; 32], minor: u8) -> Vec<u8> {
    const SUITES: &[u16] = &[
        0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0xc013, 0xc014, 0xc009, 0xc00a, 0x009c,
        0x009d, 0x002f, 0x0035, 0x000a, 0x00ff,
    ];
    let mut exts = Vec::new();
    // supported_groups: x25519, secp256r1, secp384r1
    extension(
        &mut exts,
        0x000a,
        &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18],
    );
    // ec_point_formats: uncompressed
    extension(&mut exts, 0x000b, &[0x01, 0x00]);
    // signature_algorithms
    let sigs: &[u16] = &[
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201,
    ];
    let mut body = u16be(sigs.len() * 2).to_vec();
    sigs.iter()
        .for_each(|s| body.extend_from_slice(&s.to_be_bytes()));
    extension(&mut exts, 0x000d, &body);
    // extended_master_secret
    extension(&mut exts, 0x0017, &[]);

    let mut hello = vec![0x03, minor];
    hello.extend_from_slice(random);
    hello.push(0); // empty session id
    hello.extend_from_slice(&u16be(SUITES.len() * 2));
    SUITES
        .iter()
        .for_each(|s| hello.extend_from_slice(&s.to_be_bytes()));
    hello.extend_from_slice(&[0x01, 0x00]); // compression: null
    hello.extend_from_slice(&u16be(exts.len()));
    hello.extend_from_slice(&exts);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&u24be(hello.len()));
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&u16be(handshake.len()));
    record.extend_from_slice(&handshake);
    record
}

/// An SMB1 NEGOTIATE over a NetBIOS session header, offering NT LM 0.12
/// and the SMB 2 dialects. Servers that speak SMB 2+ answer in SMB 2.
pub fn smb_negotiate() -> Vec<u8> {
    let mut dialects = Vec::new();
    for d in ["NT LM 0.12", "SMB 2.002", "SMB 2.???"] {
        dialects.push(0x02);
        dialects.extend_from_slice(d.as_bytes());
        dialects.push(0);
    }
    let mut smb = vec![0xff, b'S', b'M', b'B', 0x72]; // NEGOTIATE
    smb.extend_from_slice(&[0; 4]); // status
    smb.push(0x18); // flags: canonical paths, case-insensitive
    smb.extend_from_slice(&0xc801u16.to_le_bytes()); // flags2: unicode, NT status, long names
    smb.extend_from_slice(&[0; 12]); // pid high, signature, reserved
    smb.extend_from_slice(&[0; 2]); // tid
    smb.extend_from_slice(&0xfeffu16.to_le_bytes()); // pid
    smb.extend_from_slice(&[0; 4]); // uid, mid
    smb.push(0); // word count
    smb.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    smb.extend_from_slice(&dialects);

    let mut out = vec![0x00];
    out.extend_from_slice(&u24be(smb.len()));
    out.extend_from_slice(&smb);
    out
}

/// `{ buildinfo: 1, $db: "admin" }` as an OP_MSG (MongoDB 3.6+).
pub fn mongodb_buildinfo() -> Vec<u8> {
    let mut doc = Vec::new();
    doc.push(0x10); // int32
    doc.extend_from_slice(b"buildinfo\0");
    doc.extend_from_slice(&1i32.to_le_bytes());
    doc.push(0x02); // string
    doc.extend_from_slice(b"$db\0");
    doc.extend_from_slice(&6i32.to_le_bytes());
    doc.extend_from_slice(b"admin\0");
    doc.push(0); // end of document
    let mut bson = ((doc.len() + 4) as i32).to_le_bytes().to_vec();
    bson.extend_from_slice(&doc);

    let mut body = 0u32.to_le_bytes().to_vec(); // flag bits
    body.push(0); // section kind 0: body
    body.extend_from_slice(&bson);

    let mut msg = ((16 + body.len()) as i32).to_le_bytes().to_vec();
    msg.extend_from_slice(&0x726d_6170i32.to_le_bytes()); // request id
    msg.extend_from_slice(&0i32.to_le_bytes()); // response to
    msg.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
    msg.extend_from_slice(&body);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_lengths_are_consistent() {
        let r = tls_client_hello(&[7; 32]);
        assert_eq!(&r[..3], &[0x16, 0x03, 0x01]);
        let record_len = u16::from_be_bytes([r[3], r[4]]) as usize;
        assert_eq!(record_len, r.len() - 5);
        assert_eq!(r[5], 0x01);
        let hs_len = u32::from_be_bytes([0, r[6], r[7], r[8]]) as usize;
        assert_eq!(hs_len, r.len() - 9);
        assert_eq!(&r[9..11], &[0x03, 0x03]);
        assert_eq!(&r[11..43], &[7; 32]);
        assert_eq!(&tls10_client_hello()[9..11], &[0x03, 0x01]);
        // Extensions block length matches what's left.
        let suites = u16::from_be_bytes([r[44], r[45]]) as usize;
        let ext_at = 46 + suites + 2;
        let ext_len = u16::from_be_bytes([r[ext_at], r[ext_at + 1]]) as usize;
        assert_eq!(ext_at + 2 + ext_len, r.len());
        assert_ne!(random32(), random32());
    }

    #[test]
    fn smb_negotiate_layout() {
        let p = smb_negotiate();
        assert_eq!(p.len(), 4 + 69);
        assert_eq!(&p[..4], &[0, 0, 0, 69]);
        assert_eq!(&p[4..9], b"\xffSMBr");
        assert!(p.ends_with(b"\x02SMB 2.???\0"));
    }

    #[test]
    fn mongodb_message_layout() {
        let m = mongodb_buildinfo();
        assert_eq!(m.len(), 56);
        assert_eq!(i32::from_le_bytes([m[0], m[1], m[2], m[3]]), 56);
        assert_eq!(&m[12..16], &2013i32.to_le_bytes());
        assert_eq!(i32::from_le_bytes([m[21], m[22], m[23], m[24]]), 35);
        assert_eq!(m[55], 0);
    }
}
