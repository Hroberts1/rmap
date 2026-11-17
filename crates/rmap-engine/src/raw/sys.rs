//! Thin wrappers over the Linux socket syscalls the raw backend needs.
//!
//! This is the only place `libc` is used. Everything here is a direct
//! syscall with its error turned into `io::Error`; packet logic lives in
//! `rmap-packet` and `raw/mod.rs`.

use std::ffi::CStr;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use rmap_packet::MacAddr;
use rmap_packet::ethernet::ETHERTYPE_ARP;
use tokio::io::unix::AsyncFd;

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn check_size(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Open a non-blocking, close-on-exec socket.
fn socket(domain: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: socket() takes plain integers; a non-negative result is a
    // fresh descriptor that we alone own.
    let fd = check(unsafe {
        libc::socket(
            domain,
            kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    })?;
    // SAFETY: fd was just returned by socket() and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_int_option(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
    // SAFETY: the option value points at a live c_int of the stated size.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        // Only used for buffer sizes and IP_HDRINCL on IPPROTO_RAW, where
        // failure costs performance, not correctness.
        rmap_log::debug!(
            "setsockopt({level}, {name}) failed: {}",
            io::Error::last_os_error()
        );
    }
}

/// Register a socket with the tokio reactor. Must run inside a runtime.
pub fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: an OwnedFd keeps its descriptor open and unchanged until it
    // is dropped, and the AsyncFd owns it for that whole time.
    unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
}

/// A raw IPv4 socket for sending packets whose IP header we build
/// (`IPPROTO_RAW` implies `IP_HDRINCL`).
pub fn ipv4_send_socket() -> io::Result<OwnedFd> {
    let fd = socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)?;
    set_int_option(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, 1);
    set_int_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, 4 << 20);
    Ok(fd)
}

/// A raw IPv4 socket that receives a copy of every incoming packet of
/// `protocol` (`IPPROTO_TCP` or `IPPROTO_ICMP`), IP header included.
pub fn ipv4_recv_socket(protocol: libc::c_int) -> io::Result<OwnedFd> {
    let fd = socket(libc::AF_INET, libc::SOCK_RAW, protocol)?;
    set_int_option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, 8 << 20);
    Ok(fd)
}

/// An `AF_PACKET` socket bound to one interface that sends and receives
/// whole Ethernet frames carrying ARP.
pub fn arp_socket(ifindex: u32) -> io::Result<OwnedFd> {
    let proto = ETHERTYPE_ARP.to_be();
    let fd = socket(libc::AF_PACKET, libc::SOCK_RAW, libc::c_int::from(proto))?;
    // SAFETY: sockaddr_ll is plain data; all-zero is a valid starting value.
    let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::c_ushort;
    addr.sll_protocol = proto;
    addr.sll_ifindex = ifindex as libc::c_int;
    // SAFETY: addr is a fully initialised sockaddr_ll and the length matches.
    check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    })?;
    Ok(fd)
}

fn sendto_v4(fd: RawFd, packet: &[u8], dst: Ipv4Addr) -> io::Result<usize> {
    // SAFETY: sockaddr_in is plain data; all-zero is a valid starting value.
    let mut addr: libc::sockaddr_in = unsafe { zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
    // SAFETY: packet is a live slice and addr is a sockaddr_in of the given length.
    check_size(unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&addr as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    })
}

fn send(fd: RawFd, frame: &[u8]) -> io::Result<usize> {
    // SAFETY: frame is a live slice of the stated length.
    check_size(unsafe { libc::send(fd, frame.as_ptr().cast(), frame.len(), 0) })
}

fn recv(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buf is a live, writable slice of the stated length.
    check_size(unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) })
}

/// Send a whole IPv4 packet to `dst`, waiting while the socket buffer is full.
pub async fn send_ipv4(fd: &AsyncFd<OwnedFd>, packet: &[u8], dst: Ipv4Addr) -> io::Result<()> {
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| sendto_v4(inner.as_raw_fd(), packet, dst)) {
            Ok(r) => return r.map(drop),
            Err(_would_block) => continue,
        }
    }
}

/// Send a frame on a bound packet socket.
pub async fn send_frame(fd: &AsyncFd<OwnedFd>, frame: &[u8]) -> io::Result<()> {
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| send(inner.as_raw_fd(), frame)) {
            Ok(r) => return r.map(drop),
            Err(_would_block) => continue,
        }
    }
}

/// Receive one packet or frame.
pub async fn recv_packet(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| recv(inner.as_raw_fd(), buf)) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

/// An IPv4-configured network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mac: Option<MacAddr>,
    pub loopback: bool,
}

impl Interface {
    /// Whether `ip` is on this interface's directly connected subnet.
    pub fn on_link(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::from(self.netmask);
        mask != 0 && u32::from(ip) & mask == u32::from(self.addr) & mask
    }
}

/// List interfaces with an IPv4 address, using `getifaddrs`.
pub fn interfaces() -> io::Result<Vec<Interface>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head we free with freeifaddrs below.
    check(unsafe { libc::getifaddrs(&mut head) })?;
    let mut v4 = Vec::new();
    let mut macs = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is a node of the list getifaddrs returned, still alive.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: ifa_addr is non-null and points at a sockaddr header.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        if family == libc::AF_INET {
            // SAFETY: AF_INET entries hold sockaddr_in addresses and masks.
            let addr = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
            let netmask = if ifa.ifa_netmask.is_null() {
                Ipv4Addr::BROADCAST
            } else {
                // SAFETY: as above, for the netmask.
                let m = unsafe { &*ifa.ifa_netmask.cast::<libc::sockaddr_in>() };
                Ipv4Addr::from(m.sin_addr.s_addr.to_ne_bytes())
            };
            v4.push((
                name,
                Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                netmask,
                ifa.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint != 0,
            ));
        } else if family == libc::AF_PACKET {
            // SAFETY: AF_PACKET entries hold sockaddr_ll link addresses.
            let ll = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_ll>() };
            let mac = (ll.sll_halen == 6).then(|| {
                let mut m = [0u8; 6];
                m.copy_from_slice(&ll.sll_addr[..6]);
                MacAddr(m)
            });
            macs.push((name, ll.sll_ifindex as u32, mac));
        }
    }
    // SAFETY: head came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(v4
        .into_iter()
        .map(|(name, addr, netmask, loopback)| {
            let link = macs.iter().find(|(n, ..)| *n == name);
            Interface {
                index: link.map_or(0, |l| l.1),
                mac: link.and_then(|l| l.2),
                name,
                addr,
                netmask,
                loopback,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_link() {
        let i = Interface {
            name: "eth0".into(),
            index: 2,
            addr: Ipv4Addr::new(192, 168, 1, 10),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mac: None,
            loopback: false,
        };
        assert!(i.on_link(Ipv4Addr::new(192, 168, 1, 200)));
        assert!(!i.on_link(Ipv4Addr::new(192, 168, 2, 1)));
        let none = Interface {
            netmask: Ipv4Addr::UNSPECIFIED,
            ..i
        };
        assert!(!none.on_link(Ipv4Addr::new(192, 168, 1, 200)));
    }

    #[test]
    fn listing_interfaces_works_unprivileged() {
        let list = interfaces().expect("getifaddrs");
        // Loopback may be down inside a fresh network namespace, but the
        // call itself must succeed.
        for i in &list {
            assert!(!i.name.is_empty());
        }
    }
}
