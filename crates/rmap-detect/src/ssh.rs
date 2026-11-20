//! Unauthenticated SSH handshake probe (RFC 4253), stopped before encryption.
//!
//! After the banner, rmap sends its own identification and a `KEXINIT`,
//! reads the server's algorithm lists, then sends a curve25519
//! `KEX_ECDH_INIT` so the server answers with its host key. The key is
//! fingerprinted (`ssh-keygen -l` style) and the connection is dropped. No
//! keys are derived and no signature is checked, so there is no crypto here
//! beyond hashing the public key blob.
//!
//! TODO: the authentication methods list (whether `password` is offered)
//! needs `SSH_MSG_USERAUTH_REQUEST` "none", which is only allowed after
//! NEWKEYS, i.e. a completed key exchange and encryption. Out of scope: rmap
//! implements no ciphers.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use rmap_core::Service;
use rmap_core::sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{SNIPPET, escape};

const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_UNIMPLEMENTED: u8 = 3;
const MSG_DEBUG: u8 = 4;
const MSG_KEXINIT: u8 = 20;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;

/// RFC 4253 6.1: implementations must handle packets of 35000 bytes.
const MAX_PACKET: usize = 35_000;
/// Longest identification or pre-banner line we accept.
const MAX_LINE: usize = 1024;
/// Pre-banner lines skipped before giving up.
const MAX_LINES: usize = 16;
/// Packets read while waiting for one message (skipping IGNORE/DEBUG).
const MAX_PACKETS: usize = 8;
/// RFC 4251 6: algorithm names are at most 64 characters.
const MAX_NAME: usize = 64;

const IDENT: &[u8] = b"SSH-2.0-rmap\r\n";
const KEX: &[&str] = &["curve25519-sha256", "curve25519-sha256@libssh.org"];
/// Host key algorithms we ask for, best first. Older ones only widen what
/// servers will talk to; we never verify a signature.
const HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];
/// Offered so the server finds a match and keeps talking; never used.
const CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-cbc",
    "aes256-cbc",
    "3des-cbc",
];
const MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
];
/// A valid curve25519 public value (the base point, u = 9). Low-order
/// points would make the server reject the exchange; this one never does.
const EPHEMERAL: [u8; 32] = {
    let mut q = [0u8; 32];
    q[0] = 9;
    q
};

/// Algorithms a server offered in its KEXINIT (client-to-server lists).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KexInit {
    pub kex: Vec<String>,
    pub host_keys: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
}

/// What the handshake learned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Handshake {
    pub kexinit: KexInit,
    /// `<keytype> SHA256:<base64>`, when the server sent its host key.
    pub fingerprint: Option<String>,
}

/// Run the handshake against `addr` within `wait` and fold what it learned
/// into `service`. Failures only cost the extra detail.
pub async fn enrich(service: &mut Service, addr: SocketAddr, connect: Duration, wait: Duration) {
    if wait.is_zero() {
        return;
    }
    match timeout(wait, handshake(addr, connect)).await {
        Ok(Ok(h)) => {
            rmap_log::debug!(
                "service {addr}: ssh handshake: {} kex, {} host key algorithms, key {}",
                h.kexinit.kex.len(),
                h.kexinit.host_keys.len(),
                h.fingerprint.as_deref().unwrap_or("not received")
            );
            apply(service, &h);
        }
        Ok(Err(e)) => rmap_log::debug!("service {addr}: ssh handshake failed: {e}"),
        Err(_) => rmap_log::debug!("service {addr}: ssh handshake timed out"),
    }
}

/// Record the fingerprint and the hints the algorithm lists give.
pub fn apply(service: &mut Service, h: &Handshake) {
    if let Some(fp) = &h.fingerprint
        && !service.fingerprints.contains(fp)
    {
        service.fingerprints.push(fp.clone());
    }
    // GSSAPI key exchange (`gss-*`) comes from a downstream patch carried
    // by RHEL, Fedora, Oracle, Rocky and Alma; upstream OpenSSH has none.
    // It only shows when the host is set up for Kerberos key exchange.
    if h.kexinit.kex.iter().any(|k| k.starts_with("gss-")) {
        if service.os_hint.is_none() {
            service.os_hint = Some("Red Hat family Linux".to_string());
        }
        push_info(&mut service.info, "kex: gssapi-keyex");
    }
    let weak = weak(&h.kexinit);
    if !weak.is_empty() {
        push_info(
            &mut service.info,
            &format!("weak algorithms offered: {}", weak.join(", ")),
        );
    }
}

fn push_info(info: &mut Option<String>, note: &str) {
    *info = Some(match info.take() {
        Some(i) if !i.is_empty() => format!("{i}; {note}"),
        _ => note.to_string(),
    });
}

/// Offered algorithms that are broken or SHA-1/MD5 based, deduplicated.
pub fn weak(k: &KexInit) -> Vec<&str> {
    let kex = k.kex.iter().filter(|n| {
        matches!(
            n.as_str(),
            "diffie-hellman-group1-sha1"
                | "diffie-hellman-group14-sha1"
                | "diffie-hellman-group-exchange-sha1"
        )
    });
    let keys = k
        .host_keys
        .iter()
        .filter(|n| matches!(n.as_str(), "ssh-rsa" | "ssh-dss"));
    let ciphers = k.ciphers.iter().filter(|n| {
        n.ends_with("-cbc") || n.ends_with("-cbc@openssh.com") || n.starts_with("arcfour")
    });
    let macs = k
        .macs
        .iter()
        .filter(|n| n.starts_with("hmac-md5") || *n == "hmac-sha1-96");
    let mut out: Vec<&str> = Vec::new();
    for n in kex.chain(keys).chain(ciphers).chain(macs) {
        if !out.contains(&n.as_str()) {
            out.push(n);
        }
    }
    out
}

/// Connect, exchange identifications and KEXINITs, ask for the host key,
/// then say goodbye.
async fn handshake(addr: SocketAddr, connect: Duration) -> io::Result<Handshake> {
    let stream = timeout(connect, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
    let mut c = Conn {
        stream,
        buf: Vec::new(),
        addr,
    };
    c.stream.write_all(IDENT).await?;
    c.read_ident().await?;
    c.send(&kexinit_payload()).await?;
    let payload = c.recv(MSG_KEXINIT).await?;
    let kexinit = parse_kexinit(&payload).ok_or_else(|| invalid("malformed KEXINIT"))?;
    let mut h = Handshake {
        kexinit,
        fingerprint: None,
    };
    // Negotiation picks our first kex the server also has (RFC 4253 7.1).
    if !KEX.iter().any(|k| h.kexinit.kex.iter().any(|s| s == k)) {
        rmap_log::debug!("service {addr}: ssh server has no curve25519 kex; no host key");
        return Ok(h);
    }
    c.send(&ecdh_init_payload()).await?;
    match c.recv(MSG_KEX_ECDH_REPLY).await {
        Ok(reply) => h.fingerprint = parse_ecdh_reply(&reply).and_then(fingerprint),
        // Keep the algorithm lists we already have.
        Err(e) => rmap_log::debug!("service {addr}: ssh host key not received: {e}"),
    }
    let _ = c.send(&disconnect_payload()).await;
    Ok(h)
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

struct Conn {
    stream: TcpStream,
    /// Received bytes not yet consumed.
    buf: Vec<u8>,
    addr: SocketAddr,
}

impl Conn {
    /// Read until `buf` holds at least `n` bytes.
    async fn fill(&mut self, n: usize) -> io::Result<()> {
        let mut chunk = [0u8; 4096];
        while self.buf.len() < n {
            let got = self.stream.read(&mut chunk).await?;
            if got == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.buf.extend_from_slice(&chunk[..got]);
        }
        Ok(())
    }

    /// Skip pre-banner lines up to the server's `SSH-` identification.
    async fn read_ident(&mut self) -> io::Result<()> {
        for _ in 0..MAX_LINES {
            let end = loop {
                if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                    break i + 1;
                }
                if self.buf.len() >= MAX_LINE {
                    return Err(invalid("identification line too long"));
                }
                let want = self.buf.len() + 1;
                self.fill(want).await?;
            };
            if end > MAX_LINE {
                return Err(invalid("identification line too long"));
            }
            let line: Vec<u8> = self.buf.drain(..end).collect();
            rmap_log::trace!("ssh {}: <- line {}", self.addr, escape(&line, SNIPPET));
            if line.starts_with(b"SSH-") {
                return if line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-") {
                    Ok(())
                } else {
                    Err(invalid("server does not speak SSH 2"))
                };
            }
        }
        Err(invalid("no SSH identification"))
    }

    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        rmap_log::trace!(
            "ssh {}: -> msg {} ({} bytes)",
            self.addr,
            payload[0],
            payload.len()
        );
        self.stream.write_all(&frame(payload)).await
    }

    /// The payload of the next packet of type `want`, skipping IGNORE,
    /// DEBUG and UNIMPLEMENTED. DISCONNECT and anything else end the probe.
    async fn recv(&mut self, want: u8) -> io::Result<Vec<u8>> {
        for _ in 0..MAX_PACKETS {
            self.fill(4).await?;
            let total = packet_len(&self.buf).ok_or_else(|| invalid("bad packet length"))?;
            self.fill(total).await?;
            let packet: Vec<u8> = self.buf.drain(..total).collect();
            let payload = unframe(&packet).ok_or_else(|| invalid("bad packet padding"))?;
            rmap_log::trace!(
                "ssh {}: <- msg {} ({} bytes): {}",
                self.addr,
                payload[0],
                payload.len(),
                escape(payload, SNIPPET)
            );
            match payload[0] {
                t if t == want => return Ok(payload.to_vec()),
                MSG_IGNORE | MSG_DEBUG | MSG_UNIMPLEMENTED => continue,
                MSG_DISCONNECT => return Err(invalid("server disconnected")),
                t => return Err(invalid(&format!("unexpected message {t}"))),
            }
        }
        Err(invalid("too many packets"))
    }
}

/// Wrap `payload` in an unencrypted binary packet (RFC 4253 6): length,
/// padding length, payload, at least 4 bytes of padding, total a multiple
/// of 8. Zero padding is fine without a cipher.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut pad = 8 - (5 + payload.len()) % 8;
    if pad < 4 {
        pad += 8;
    }
    let len = 1 + payload.len() + pad;
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.resize(4 + len, 0);
    out
}

/// Total size (length field included) of the packet starting `buf`, once
/// its first 4 bytes are known; `None` if out of bounds.
pub fn packet_len(buf: &[u8]) -> Option<usize> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    // Padding length byte, a message type, and 4 bytes of padding.
    (6..=MAX_PACKET).contains(&len).then_some(4 + len)
}

/// The payload of one complete packet; `None` if malformed or empty.
pub fn unframe(packet: &[u8]) -> Option<&[u8]> {
    let total = packet_len(packet)?;
    if packet.len() != total {
        return None;
    }
    let pad = *packet.get(4)? as usize;
    let end = total.checked_sub(pad)?;
    if pad < 4 || end <= 5 {
        return None;
    }
    Some(&packet[5..end])
}

/// Our KEXINIT: no cookie randomness is needed since we never finish.
fn kexinit_payload() -> Vec<u8> {
    let mut p = vec![MSG_KEXINIT];
    p.extend_from_slice(&[0u8; 16]);
    let lists: [&[&str]; 10] = [
        KEX,
        HOST_KEYS,
        CIPHERS,
        CIPHERS,
        MACS,
        MACS,
        &["none"],
        &["none"],
        &[],
        &[],
    ];
    for list in lists {
        put_string(&mut p, list.join(",").as_bytes());
    }
    p.push(0); // first_kex_packet_follows
    p.extend_from_slice(&[0; 4]); // reserved
    p
}

fn ecdh_init_payload() -> Vec<u8> {
    let mut p = vec![MSG_KEX_ECDH_INIT];
    put_string(&mut p, &EPHEMERAL);
    p
}

fn disconnect_payload() -> Vec<u8> {
    let mut p = vec![MSG_DISCONNECT];
    p.extend_from_slice(&11u32.to_be_bytes()); // SSH_DISCONNECT_BY_APPLICATION
    put_string(&mut p, b"");
    put_string(&mut p, b"");
    p
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Read an SSH `string` from the front of `buf`, advancing it.
fn take_string<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let s = buf.get(4..4usize.checked_add(len)?)?;
    *buf = &buf[4 + len..];
    Some(s)
}

/// A comma-separated list of algorithm names. Every name must be 1-64
/// printable ASCII characters, so they are safe to show as-is.
fn take_name_list(buf: &mut &[u8]) -> Option<Vec<String>> {
    let raw = take_string(buf)?;
    if raw.is_empty() {
        return Some(Vec::new());
    }
    raw.split(|&b| b == b',')
        .map(|n| {
            let ok =
                (1..=MAX_NAME).contains(&n.len()) && n.iter().all(|b| (0x21..0x7f).contains(b));
            ok.then(|| String::from_utf8_lossy(n).into_owned())
        })
        .collect()
}

/// Parse a KEXINIT payload (message type included).
pub fn parse_kexinit(payload: &[u8]) -> Option<KexInit> {
    let mut b = payload.strip_prefix(&[MSG_KEXINIT])?.get(16..)?;
    let kex = take_name_list(&mut b)?;
    let host_keys = take_name_list(&mut b)?;
    let ciphers = take_name_list(&mut b)?;
    take_name_list(&mut b)?; // server-to-client ciphers
    let macs = take_name_list(&mut b)?;
    // The other direction's MACs, compression both ways, languages.
    for _ in 0..5 {
        take_name_list(&mut b)?;
    }
    // first_kex_packet_follows and reserved.
    if b.len() < 5 {
        return None;
    }
    Some(KexInit {
        kex,
        host_keys,
        ciphers,
        macs,
    })
}

/// The host key blob `K_S` of a KEX_ECDH_REPLY payload.
pub fn parse_ecdh_reply(payload: &[u8]) -> Option<&[u8]> {
    let mut b = payload.strip_prefix(&[MSG_KEX_ECDH_REPLY])?;
    let ks = take_string(&mut b)?;
    take_string(&mut b)?; // Q_S
    take_string(&mut b)?; // signature
    Some(ks)
}

/// `<keytype> SHA256:<base64, no padding>` of a host key blob, as
/// `ssh-keygen -l` prints it. The key type is the blob's first string.
pub fn fingerprint(blob: &[u8]) -> Option<String> {
    let mut b = blob;
    let kind = take_string(&mut b)?;
    if !(1..=MAX_NAME).contains(&kind.len()) || !kind.iter().all(|c| (0x21..0x7f).contains(c)) {
        return None;
    }
    let kind = String::from_utf8_lossy(kind);
    Some(format!("{kind} SHA256:{}", base64(&sha256::digest(blob))))
}

/// Standard base64 (RFC 4648 section 4) without `=` padding.
fn base64(data: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(ABC[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public half of an ed25519 key made with `ssh-keygen -t ed25519` for
    /// this test. `ssh-keygen -lf` printed
    /// `256 SHA256:94M7zGojZRvqqf2k1YRyUQKm1PCRNrfmIAmrlOzONeE no comment (ED25519)`.
    const ED25519_PUB: [u8; 32] = [
        0x71, 0xd1, 0xfc, 0xf6, 0x21, 0x6f, 0x5c, 0x3e, 0x7d, 0xb1, 0x75, 0x2e, 0xd6, 0x9f, 0x9a,
        0x86, 0x3c, 0x48, 0x82, 0xa0, 0x4f, 0xa0, 0x29, 0xd1, 0xe1, 0x2c, 0x65, 0x89, 0xe5, 0xf5,
        0x95, 0x0f,
    ];
    const ED25519_FP: &str = "ssh-ed25519 SHA256:94M7zGojZRvqqf2k1YRyUQKm1PCRNrfmIAmrlOzONeE";

    fn ed25519_blob() -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, &ED25519_PUB);
        b
    }

    fn server_kexinit(kex: &str, host_keys: &str, ciphers: &str, macs: &str) -> Vec<u8> {
        let mut p = vec![MSG_KEXINIT];
        p.extend_from_slice(&[0xaa; 16]);
        for l in [
            kex, host_keys, ciphers, ciphers, macs, macs, "none", "none", "", "",
        ] {
            put_string(&mut p, l.as_bytes());
        }
        p.extend_from_slice(&[0; 5]);
        p
    }

    fn ecdh_reply(blob: &[u8]) -> Vec<u8> {
        let mut p = vec![MSG_KEX_ECDH_REPLY];
        put_string(&mut p, blob);
        put_string(&mut p, &[7; 32]);
        put_string(&mut p, b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x40fake");
        p
    }

    #[test]
    fn framing_round_trips_and_pads() {
        for n in [1, 2, 3, 4, 7, 8, 100, 1000] {
            let payload: Vec<u8> = (0..n).map(|i| i as u8 | 1).collect();
            let f = frame(&payload);
            assert_eq!(f.len() % 8, 0, "n={n}");
            assert!(f[4] >= 4);
            assert_eq!(packet_len(&f), Some(f.len()));
            assert_eq!(unframe(&f), Some(&payload[..]));
        }
    }

    #[test]
    fn framing_rejects_bad_lengths() {
        assert_eq!(packet_len(&[0, 0, 0]), None);
        assert_eq!(packet_len(&[0, 0, 0, 5]), None);
        assert_eq!(packet_len(&35_001u32.to_be_bytes()), None);
        assert_eq!(packet_len(&u32::MAX.to_be_bytes()), None);
        assert_eq!(packet_len(&35_000u32.to_be_bytes()), Some(35_004));
        // Padding longer than the packet, under 4, or leaving no payload.
        assert_eq!(unframe(&[0, 0, 0, 8, 200, 20, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(unframe(&[0, 0, 0, 8, 3, 20, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(unframe(&[0, 0, 0, 8, 7, 20, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(
            unframe(&[0, 0, 0, 8, 6, 20, 0, 0, 0, 0, 0, 0]),
            Some(&[20u8][..])
        );
        // Truncated packet.
        assert_eq!(unframe(&[0, 0, 0, 8, 4, 20, 0]), None);
    }

    #[test]
    fn parses_kexinit() {
        let p = server_kexinit(
            "curve25519-sha256,gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
            "rsa-sha2-512,ssh-ed25519",
            "aes256-gcm@openssh.com,aes128-cbc",
            "hmac-sha2-256,hmac-md5",
        );
        let k = parse_kexinit(&p).unwrap();
        assert_eq!(
            k.kex,
            ["curve25519-sha256", "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g=="]
        );
        assert_eq!(k.host_keys, ["rsa-sha2-512", "ssh-ed25519"]);
        assert_eq!(k.ciphers, ["aes256-gcm@openssh.com", "aes128-cbc"]);
        assert_eq!(k.macs, ["hmac-sha2-256", "hmac-md5"]);
        // Our own KEXINIT parses too.
        assert_eq!(parse_kexinit(&kexinit_payload()).unwrap().kex, KEX);
    }

    #[test]
    fn kexinit_rejects_unsafe_names_and_truncation() {
        let p = server_kexinit(
            "curve25519-sha256,\x1b[31m",
            "ssh-ed25519",
            "aes128-ctr",
            "x",
        );
        assert_eq!(parse_kexinit(&p), None);
        let p = server_kexinit("a,,b", "ssh-ed25519", "aes128-ctr", "x");
        assert_eq!(parse_kexinit(&p), None);
        let long = "a".repeat(65);
        let p = server_kexinit(&long, "ssh-ed25519", "aes128-ctr", "x");
        assert_eq!(parse_kexinit(&p), None);
        let p = server_kexinit("curve25519-sha256", "ssh-ed25519", "aes128-ctr", "x");
        for cut in 0..p.len() - 5 {
            assert_eq!(parse_kexinit(&p[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        assert_eq!(fingerprint(&ed25519_blob()).as_deref(), Some(ED25519_FP));
        let reply = ecdh_reply(&ed25519_blob());
        assert_eq!(parse_ecdh_reply(&reply), Some(&ed25519_blob()[..]));
        assert_eq!(parse_ecdh_reply(&reply[..reply.len() - 1]), None);
        assert_eq!(fingerprint(b"\x00\x00\x00\x02\x1b["), None);
        assert_eq!(fingerprint(b""), None);
    }

    #[test]
    fn base64_without_padding() {
        // RFC 4648 section 10 vectors with the `=` removed.
        for (i, o) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn gss_kex_hints_red_hat_family() {
        let mut s = Service {
            name: "ssh".into(),
            info: Some("protocol 2.0".into()),
            ..Default::default()
        };
        let h = Handshake {
            kexinit: KexInit {
                kex: vec!["gss-curve25519-sha256-toWM5Slw5Ew8Mqkay+al2g==".into()],
                ..Default::default()
            },
            fingerprint: Some(ED25519_FP.into()),
        };
        apply(&mut s, &h);
        apply(&mut s, &Handshake::default());
        assert_eq!(s.os_hint.as_deref(), Some("Red Hat family Linux"));
        assert_eq!(s.info.as_deref(), Some("protocol 2.0; kex: gssapi-keyex"));
        assert_eq!(s.fingerprints, [ED25519_FP]);
        // A banner's own OS hint wins; no gss kex, no hint.
        let mut s = Service {
            os_hint: Some("Ubuntu Linux".into()),
            ..Default::default()
        };
        apply(&mut s, &h);
        assert_eq!(s.os_hint.as_deref(), Some("Ubuntu Linux"));
        let mut s = Service::default();
        apply(&mut s, &Handshake::default());
        assert_eq!((s.os_hint, s.info), (None, None));
    }

    #[test]
    fn weak_algorithms_note() {
        let k = KexInit {
            kex: vec![
                "curve25519-sha256".into(),
                "diffie-hellman-group1-sha1".into(),
            ],
            host_keys: vec!["ssh-ed25519".into(), "ssh-rsa".into()],
            ciphers: vec![
                "aes128-ctr".into(),
                "aes128-cbc".into(),
                "arcfour256".into(),
            ],
            macs: vec!["hmac-sha2-256".into(), "hmac-md5".into(), "hmac-md5".into()],
        };
        assert_eq!(
            weak(&k),
            [
                "diffie-hellman-group1-sha1",
                "ssh-rsa",
                "aes128-cbc",
                "arcfour256",
                "hmac-md5"
            ]
        );
        let mut s = Service::default();
        apply(
            &mut s,
            &Handshake {
                kexinit: k,
                fingerprint: None,
            },
        );
        assert_eq!(
            s.info.as_deref(),
            Some(
                "weak algorithms offered: diffie-hellman-group1-sha1, ssh-rsa, aes128-cbc, arcfour256, hmac-md5"
            )
        );
    }

    /// A fake sshd on loopback: banner, wait for the client's
    /// identification, KEXINIT, and the host key once the ECDH_INIT arrives.
    async fn fake_sshd(banner: &'static [u8], kexinit: Vec<u8>, reply: Vec<u8>) -> SocketAddr {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let (kexinit, reply) = (frame(&kexinit), frame(&reply));
                tokio::spawn(async move {
                    let _ = s.write_all(banner).await;
                    let mut got = Vec::new();
                    let mut chunk = [0u8; 2048];
                    let mut sent_kexinit = false;
                    let init = frame(&ecdh_init_payload());
                    while let Ok(Ok(n @ 1..)) =
                        timeout(Duration::from_secs(10), s.read(&mut chunk)).await
                    {
                        got.extend_from_slice(&chunk[..n]);
                        if !sent_kexinit && got.contains(&b'\n') {
                            sent_kexinit = true;
                            let _ = s.write_all(&kexinit).await;
                        }
                        if got.windows(init.len()).any(|w| w == init) {
                            let _ = s.write_all(&reply).await;
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    fn timing() -> rmap_core::Timing {
        rmap_core::Timing {
            connect_timeout: Duration::from_secs(2),
            ..rmap_core::Timing::template(4)
        }
    }

    #[tokio::test]
    async fn red_hat_sshd_end_to_end() {
        let kexinit = server_kexinit(
            "curve25519-sha256,curve25519-sha256@libssh.org,gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
            "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
            "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr",
            "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
        );
        let addr = fake_sshd(
            b"SSH-2.0-OpenSSH_9.9\r\n",
            kexinit,
            ecdh_reply(&ed25519_blob()),
        )
        .await;
        let s = crate::Detector::builtin()
            .detect(addr, rmap_core::Protocol::Tcp, &timing(), 22)
            .await
            .unwrap();
        assert_eq!(s.version_label().as_deref(), Some("OpenSSH 9.9"));
        assert_eq!(s.fingerprints, [ED25519_FP]);
        assert_eq!(s.os_hint.as_deref(), Some("Red Hat family Linux"));
        assert!(
            s.info.as_deref().unwrap().contains("kex: gssapi-keyex"),
            "{:?}",
            s.info
        );
        assert!(!s.info.as_deref().unwrap().contains("weak"), "{:?}", s.info);
    }

    #[tokio::test]
    async fn no_curve25519_still_reports_algorithms() {
        let kexinit = server_kexinit(
            "diffie-hellman-group14-sha1",
            "ssh-rsa",
            "aes128-cbc",
            "hmac-sha1",
        );
        let addr = fake_sshd(b"SSH-2.0-dropbear_2014.63\r\n", kexinit, Vec::new()).await;
        let mut s = Service::default();
        enrich(&mut s, addr, Duration::from_secs(2), Duration::from_secs(5)).await;
        assert!(s.fingerprints.is_empty());
        assert_eq!(s.os_hint, None);
        assert_eq!(
            s.info.as_deref(),
            Some("weak algorithms offered: diffie-hellman-group14-sha1, ssh-rsa, aes128-cbc")
        );
    }

    #[tokio::test]
    async fn print_ports_get_no_handshake() {
        // An SSH banner on 9100 must not make rmap send anything there.
        let kexinit = server_kexinit("curve25519-sha256", "ssh-ed25519", "aes128-ctr", "x");
        let reply = ecdh_reply(&ed25519_blob());
        let addr = fake_sshd(b"SSH-2.0-OpenSSH_9.9\r\n", kexinit, reply).await;
        let s = crate::Detector::builtin()
            .detect(
                addr,
                rmap_core::Protocol::Tcp,
                &rmap_core::Timing::template(5),
                9100,
            )
            .await
            .unwrap();
        // A handshake would have fetched this server's host key.
        assert!(s.fingerprints.is_empty());
    }

    #[test]
    fn parsers_never_panic_on_random_input() {
        // xorshift: deterministic, no dependency.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let seeds = [
            server_kexinit(
                "curve25519-sha256",
                "ssh-ed25519",
                "aes128-ctr",
                "hmac-sha1",
            ),
            ecdh_reply(&ed25519_blob()),
            frame(&ecdh_reply(&ed25519_blob())),
        ];
        for i in 0..20_000 {
            let mut buf = if i % 2 == 0 {
                seeds[i % 3].clone()
            } else {
                (0..rnd() % 300).map(|_| rnd() as u8).collect()
            };
            for _ in 0..rnd() % 6 {
                if buf.is_empty() {
                    break;
                }
                let at = (rnd() as usize) % buf.len();
                buf[at] = rnd() as u8;
            }
            let _ = parse_kexinit(&buf);
            let _ = parse_ecdh_reply(&buf).and_then(fingerprint);
            let _ = fingerprint(&buf);
            let _ = packet_len(&buf);
            let _ = unframe(&buf);
        }
    }
}
