//! Host name lookup for scanned addresses, so a host list shows
//! `FRONTDESK-PC` instead of a bare IP. Three sources, because no single
//! one names everything on a typical small-office network:
//!
//! - **Reverse DNS**: a PTR query to a DNS server. Names domain-joined and
//!   DHCP-registered machines.
//! - **NetBIOS**: a node status request to the host's UDP 137. Names
//!   Windows PCs, Samba, most NAS boxes and many printers.
//! - **mDNS**: a unicast PTR query to the host's own responder on UDP
//!   5353. Names Macs, phones, Linux, printers and a lot of IoT.
//!
//! Every lookup is one small UDP exchange on a connected socket, so only
//! replies from the address asked are read. Names come from the network
//! and are cleaned with `rmap_core::names::clean` before they leave here.

mod dns;

use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rmap_core::{HostName, NameSource};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

pub const NETBIOS_PORT: u16 = 137;
pub const MDNS_PORT: u16 = 5353;
pub const DNS_PORT: u16 = 53;

/// Largest reply read. NetBIOS name tables and mDNS replies fit easily.
const MAX_REPLY: usize = 4096;

/// Reverse DNS for `ip`, asking `server`.
pub async fn reverse_dns(ip: IpAddr, server: SocketAddr, wait: Duration) -> Option<HostName> {
    let qname = dns::reverse_name(ip);
    let id = query_id(ip, 0);
    let q = dns::query(id, true, &labels(&qname), dns::TYPE_PTR, dns::CLASS_IN);
    let qname = qname.join(".");
    let name = exchange(server, &q, wait, |r| {
        let recs = dns::answers(r, Some(id))?;
        dns::ptr_target(r, &recs, &qname)
    })
    .await?;
    rmap_log::trace!("reverse DNS {ip} via {server}: {name:?}");
    HostName::new(&name, NameSource::Dns)
}

/// The host's NetBIOS workstation name, asking `ip` on UDP 137.
pub async fn netbios(ip: IpAddr, wait: Duration) -> Option<HostName> {
    netbios_at(SocketAddr::new(ip, NETBIOS_PORT), wait).await
}

async fn netbios_at(addr: SocketAddr, wait: Duration) -> Option<HostName> {
    let id = query_id(addr.ip(), 1);
    // A node status request for the wildcard name `*`, first-level encoded
    // (each nibble of the space-padded 16-byte name becomes 'A' + n).
    let mut wildcard = [0u8; 16];
    wildcard[0] = b'*';
    let encoded: Vec<u8> = wildcard
        .iter()
        .flat_map(|b| [b'A' + (b >> 4), b'A' + (b & 0x0f)])
        .collect();
    let q = dns::query(id, false, &[&encoded], dns::TYPE_NBSTAT, dns::CLASS_IN);
    let name = exchange(addr, &q, wait, |r| {
        let recs = dns::answers(r, Some(id))?;
        let rec = recs.iter().find(|rec| rec.kind == dns::TYPE_NBSTAT)?;
        workstation_name(r.get(rec.data.clone())?)
    })
    .await?;
    rmap_log::trace!("NetBIOS {addr}: {name:?}");
    HostName::new(&name, NameSource::Netbios)
}

/// The first unique (not group) name with the workstation suffix 0x00
/// from a node status name table.
fn workstation_name(data: &[u8]) -> Option<String> {
    let count = *data.first()? as usize;
    let table = data.get(1..1 + count * 18)?;
    table
        .as_chunks::<18>()
        .0
        .iter()
        .find(|e| e[15] == 0x00 && e[16] & 0x80 == 0)
        .map(|e| String::from_utf8_lossy(e[..15].trim_ascii_end()).into_owned())
        .filter(|n| !n.is_empty())
}

/// The name the host's own mDNS responder gives for `ip`, asking it
/// directly on UDP 5353 for a unicast reply.
pub async fn mdns(ip: IpAddr, wait: Duration) -> Option<HostName> {
    mdns_at(ip, SocketAddr::new(ip, MDNS_PORT), wait).await
}

async fn mdns_at(ip: IpAddr, addr: SocketAddr, wait: Duration) -> Option<HostName> {
    let qname = dns::reverse_name(ip);
    let id = query_id(ip, 2);
    let q = dns::query(
        id,
        false,
        &labels(&qname),
        dns::TYPE_PTR,
        dns::CLASS_IN | dns::CLASS_UNICAST,
    );
    let qname = qname.join(".");
    let name = exchange(addr, &q, wait, |r| {
        // Legacy unicast replies echo the id (RFC 6762 section 6.7), but
        // some responders send 0; the connected socket already ties the
        // reply to the host asked.
        let recs = dns::answers(r, Some(id)).or_else(|| dns::answers(r, Some(0)))?;
        dns::ptr_target(r, &recs, &qname)
    })
    .await?;
    rmap_log::trace!("mDNS {addr}: {name:?}");
    HostName::new(&name, NameSource::Mdns)
}

/// The system's first DNS server, read from `/etc/resolv.conf` on Unix.
/// Windows keeps it in the registry, which std can't read, so there the
/// user sets one on the setup form.
pub fn system_dns_server() -> Option<SocketAddr> {
    #[cfg(unix)]
    {
        let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
        parse_resolv_conf(&conf)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn parse_resolv_conf(conf: &str) -> Option<SocketAddr> {
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| {
            // Drop an IPv6 zone (`fe80::1%eth0`); std can't parse it.
            let addr = rest.trim().split('%').next()?;
            addr.parse::<IpAddr>().ok()
        })
        .map(|ip| SocketAddr::new(ip, DNS_PORT))
        .next()
}

/// Order names best first and drop exact repeats (ignoring case): DNS
/// names first (an admin chose them), then NetBIOS, then mDNS.
pub fn rank(mut names: Vec<HostName>) -> Vec<HostName> {
    names.sort_by_key(|n| n.source);
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.name.to_ascii_lowercase()));
    names
}

/// Send `query` to `addr` and return the first reply `decode` accepts,
/// or `None` on timeout or a socket error (an ICMP unreachable shows up
/// as one on most systems).
async fn exchange<T>(
    addr: SocketAddr,
    query: &[u8],
    wait: Duration,
    decode: impl Fn(&[u8]) -> Option<T>,
) -> Option<T> {
    let local: SocketAddr = match addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(local).await.ok()?;
    sock.connect(addr).await.ok()?;
    sock.send(query).await.ok()?;
    let deadline = Instant::now() + wait;
    let mut buf = vec![0u8; MAX_REPLY];
    loop {
        let n = timeout_at(deadline, sock.recv(&mut buf)).await.ok()?.ok()?;
        if let Some(found) = decode(&buf[..n]) {
            return Some(found);
        }
    }
}

/// A query id that differs per host and per kind of query, so a stray
/// reply to one can't be taken for another.
fn query_id(ip: IpAddr, kind: u8) -> u16 {
    RandomState::new().hash_one((ip, kind)) as u16
}

fn labels(name: &[String]) -> Vec<&[u8]> {
    name.iter().map(|l| l.as_bytes()).collect()
}

#[cfg(test)]
mod tests;
