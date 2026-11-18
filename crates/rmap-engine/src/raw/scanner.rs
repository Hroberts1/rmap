//! Raw sockets on Linux: send hand-built packets, read replies on
//! listener tasks, and hand each matched reply to the probe waiting for it.

use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmap_core::{PortResult, PortState, Protocol, ScanType, Timing};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{sleep, timeout};

use super::matcher::{Matched, Matcher, Reply, Route, tcp_state, udp_state};
use super::sys::{self, Interface};
use crate::Stats;
use crate::payloads::udp_payload;
use crate::rate::RateLimiter;

type PortKey = (IpAddr, u16, Protocol);

/// Probes waiting for a reply, keyed by what the reply will be about.
struct Waiters<K, V> {
    map: Mutex<HashMap<K, (u64, oneshot::Sender<V>)>>,
    next_id: AtomicU64,
}

impl<K: Eq + Hash + Copy, V> Waiters<K, V> {
    fn new() -> Self {
        Waiters {
            map: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, (u64, oneshot::Sender<V>)>> {
        self.map.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Wait for the next reply about `key`. Dropping the registration stops
    /// waiting.
    fn register(&self, key: K) -> (Registration<'_, K, V>, oneshot::Receiver<V>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.lock().insert(key, (id, tx));
        (
            Registration {
                waiters: self,
                key,
                id,
            },
            rx,
        )
    }

    /// Hand a reply to whoever waits for it. Unwanted replies (duplicates,
    /// answers after a timeout) are dropped.
    fn deliver(&self, key: K, value: V) -> bool {
        match self.lock().remove(&key) {
            Some((_, tx)) => tx.send(value).is_ok(),
            None => false,
        }
    }
}

struct Registration<'a, K: Eq + Hash + Copy, V> {
    waiters: &'a Waiters<K, V>,
    key: K,
    id: u64,
}

impl<K: Eq + Hash + Copy, V> Drop for Registration<'_, K, V> {
    fn drop(&mut self) {
        let mut map = self.waiters.lock();
        if map.get(&self.key).is_some_and(|(id, _)| *id == self.id) {
            map.remove(&self.key);
        }
    }
}

/// State shared between probes and listener tasks.
struct Inner {
    matcher: Matcher,
    send: AsyncFd<OwnedFd>,
    /// `None` when raw IPv6 sockets couldn't be opened (for example, IPv6
    /// is disabled); IPv6 targets then get unprivileged probes.
    send6: Option<AsyncFd<OwnedFd>>,
    rate: RateLimiter,
    ports: Waiters<PortKey, Reply>,
    pings: Waiters<IpAddr, ()>,
}

impl Inner {
    fn dispatch(&self, m: Matched) {
        match m {
            Matched::Port {
                ip,
                port,
                protocol,
                reply,
            } => {
                let taken = self.ports.deliver((ip, port, protocol), reply);
                rmap_log::trace!(
                    "reply {ip}:{port}/{} {reply:?} wanted={taken}",
                    protocol.as_str()
                );
            }
            Matched::HostUp(ip) => {
                let taken = self.pings.deliver(ip, ());
                rmap_log::trace!("host reply from {ip} wanted={taken}");
            }
        }
    }

    async fn send(&self, packet: &[u8], dst: IpAddr) -> io::Result<Instant> {
        let fd = match dst {
            IpAddr::V4(_) => &self.send,
            IpAddr::V6(_) => self.send6.as_ref().ok_or_else(no_ipv6)?,
        };
        self.rate.wait().await;
        let sent = Instant::now();
        sys::send_ip(fd, packet, dst).await?;
        Ok(sent)
    }
}

fn no_ipv6() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "raw IPv6 sockets unavailable")
}

/// How a listener reads its socket and matches what it reads.
#[derive(Clone, Copy)]
enum Handler {
    /// IPv4 raw sockets deliver the IP header with each packet.
    V4(fn(&Matcher, &[u8]) -> Option<Matched>),
    /// IPv6 raw sockets don't; the sender comes from `recvfrom`.
    V6(fn(&Matcher, Ipv6Addr, &[u8]) -> Option<Matched>),
}

/// The IPv6 sockets, opened apart from the IPv4 ones so that a host
/// without IPv6 still gets raw IPv4 scans.
struct V6Sockets {
    send: AsyncFd<OwnedFd>,
    icmp: AsyncFd<OwnedFd>,
    tcp: Option<AsyncFd<OwnedFd>>,
    udp: Option<UdpSocket>,
}

impl V6Sockets {
    fn open(scan_type: ScanType, udp_port: u16) -> io::Result<V6Sockets> {
        let send = sys::register(sys::ipv6_send_socket()?)?;
        let icmp = sys::register(sys::ipv6_recv_socket(libc::IPPROTO_ICMPV6)?)?;
        let tcp = match scan_type {
            ScanType::Syn => Some(sys::register(sys::ipv6_recv_socket(libc::IPPROTO_TCP)?)?),
            _ => None,
        };
        // Same port as the IPv4 UDP socket, so one Matcher recognises both.
        let udp = match scan_type {
            ScanType::Udp => {
                let s = sys::udp6_socket(udp_port)?;
                Some(UdpSocket::from_std(s)?)
            }
            _ => None,
        };
        Ok(V6Sockets {
            send,
            icmp,
            tcp,
            udp,
        })
    }
}

/// The raw backend for one scan. Dropping it stops its listener tasks.
pub(crate) struct RawScanner {
    scan_type: ScanType,
    inner: Arc<Inner>,
    interfaces: Vec<Interface>,
    /// ARP sockets by interface index; `None` if one couldn't be opened.
    arp: Mutex<HashMap<u32, Option<Arc<AsyncFd<OwnedFd>>>>>,
    tasks: Mutex<Vec<AbortHandle>>,
}

impl Drop for RawScanner {
    fn drop(&mut self) {
        for t in self
            .tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
        {
            t.abort();
        }
    }
}

/// Read packets from `fd` forever, passing each to `handle`.
async fn listen(what: &'static str, fd: AsyncFd<OwnedFd>, inner: Arc<Inner>, handle: Handler) {
    let mut buf = vec![0u8; 65_536];
    let mut errors = 0u32;
    loop {
        let matched = match handle {
            Handler::V4(f) => sys::recv_packet(&fd, &mut buf)
                .await
                .map(|n| f(&inner.matcher, &buf[..n])),
            Handler::V6(f) => sys::recv_from_v6(&fd, &mut buf)
                .await
                .map(|(n, src)| f(&inner.matcher, src, &buf[..n])),
        };
        match matched {
            Ok(m) => {
                errors = 0;
                if let Some(m) = m {
                    inner.dispatch(m);
                }
            }
            Err(e) => {
                errors += 1;
                if errors == 1 {
                    rmap_log::warn!("{what} listener: receive failed: {e}");
                }
                sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Read UDP replies to our probes from the socket that owns their port.
async fn listen_udp(socket: UdpSocket, inner: Arc<Inner>) {
    let mut buf = vec![0u8; 65_536];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((_, from)) => inner.dispatch(Matched::Port {
                ip: from.ip(),
                port: from.port(),
                protocol: Protocol::Udp,
                reply: Reply::Data,
            }),
            Err(e) => {
                // ICMP errors can surface here on some kernels; the raw ICMP
                // listener handles them, so just keep reading.
                rmap_log::trace!("udp listener: {e}");
                sleep(Duration::from_millis(1)).await;
            }
        }
    }
}

impl RawScanner {
    /// Open every socket the scan needs. Fails with `PermissionDenied`
    /// without root or `CAP_NET_RAW`.
    pub(crate) fn open(scan_type: ScanType, timing: &Timing) -> io::Result<RawScanner> {
        let send = sys::register(sys::ipv4_send_socket()?)?;
        let icmp = sys::register(sys::ipv4_recv_socket(libc::IPPROTO_ICMP)?)?;
        let tcp = match scan_type {
            ScanType::Syn => Some(sys::register(sys::ipv4_recv_socket(libc::IPPROTO_TCP)?)?),
            _ => None,
        };
        // Binding a normal socket reserves the UDP source port, so the
        // kernel delivers replies to us instead of answering them with
        // port-unreachable.
        let udp = match scan_type {
            ScanType::Udp => {
                let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
                s.set_nonblocking(true)?;
                Some(UdpSocket::from_std(s)?)
            }
            _ => None,
        };
        let udp_port = match &udp {
            Some(s) => s.local_addr()?.port(),
            None => 0,
        };
        let interfaces = sys::interfaces().unwrap_or_else(|e| {
            rmap_log::warn!("could not list interfaces, ARP discovery disabled: {e}");
            Vec::new()
        });
        let v6 = V6Sockets::open(scan_type, udp_port)
            .inspect_err(|e| {
                rmap_log::info!("raw IPv6 unavailable ({e}); IPv6 targets get unprivileged probes")
            })
            .ok();
        let rate = RateLimiter::for_timing(timing);
        rmap_log::info!(
            "raw backend ready: scan={scan_type:?} rate={}pps udp_port={udp_port} ipv6={} interfaces={:?}",
            crate::rate::packet_rate(timing),
            v6.is_some(),
            interfaces
                .iter()
                .map(|i| format!("{}={}/{}", i.name, i.addr, i.netmask))
                .collect::<Vec<_>>()
        );
        let (send6, v6_listeners) = match v6 {
            Some(v6) => (Some(v6.send), Some((v6.icmp, v6.tcp, v6.udp))),
            None => (None, None),
        };
        let inner = Arc::new(Inner {
            matcher: Matcher::new(udp_port),
            send,
            send6,
            rate,
            ports: Waiters::new(),
            pings: Waiters::new(),
        });
        let spawn = |what, fd, handle| tokio::spawn(listen(what, fd, inner.clone(), handle));
        let mut tasks = vec![spawn("ICMP", icmp, Handler::V4(Matcher::match_icmp)).abort_handle()];
        if let Some(tcp) = tcp {
            tasks.push(spawn("TCP", tcp, Handler::V4(Matcher::match_tcp)).abort_handle());
        }
        if let Some(udp) = udp {
            tasks.push(tokio::spawn(listen_udp(udp, inner.clone())).abort_handle());
        }
        if let Some((icmp, tcp, udp)) = v6_listeners {
            tasks.push(spawn("ICMPv6", icmp, Handler::V6(Matcher::match_icmp6)).abort_handle());
            if let Some(tcp) = tcp {
                tasks.push(spawn("TCPv6", tcp, Handler::V6(Matcher::match_tcp6)).abort_handle());
            }
            if let Some(udp) = udp {
                tasks.push(tokio::spawn(listen_udp(udp, inner.clone())).abort_handle());
            }
        }
        Ok(RawScanner {
            scan_type,
            inner,
            interfaces,
            arp: Mutex::new(HashMap::new()),
            tasks: Mutex::new(tasks),
        })
    }

    /// The route raw probes to `dst` would take, or why there is none
    /// and the host should get unprivileged probes instead.
    pub(crate) fn route(&self, dst: IpAddr) -> io::Result<Route> {
        if let IpAddr::V6(v6) = dst {
            if self.inner.send6.is_none() {
                return Err(no_ipv6());
            }
            if v6.to_ipv4_mapped().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "IPv4-mapped addresses can't be sent on raw IPv6 sockets",
                ));
            }
        }
        super::route(dst)
    }

    /// Probe one port of `route.dst()`. Connect scans don't come here.
    pub(crate) async fn probe(
        &self,
        route: Route,
        port: u16,
        timing: &Timing,
        stats: &Stats,
    ) -> PortResult {
        let (src, dst) = (route.src(), route.dst());
        let (protocol, silent) = match self.scan_type {
            ScanType::Udp => (Protocol::Udp, PortState::OpenFiltered),
            _ => (Protocol::Tcp, PortState::Filtered),
        };
        let payload = match protocol {
            Protocol::Udp => udp_payload(port),
            Protocol::Tcp => Vec::new(),
        };
        let m = &self.inner.matcher;
        for try_no in 0..=timing.retries {
            if !timing.scan_delay.is_zero() {
                sleep(timing.scan_delay).await;
            }
            let packet = match protocol {
                Protocol::Tcp => m.syn_packet(route, port, try_no),
                Protocol::Udp => m.udp_packet(route, port, &payload),
            };
            let (_registration, reply) = self.inner.ports.register((dst, port, protocol));
            let sent = match self.inner.send(&packet, dst).await {
                Ok(t) => t,
                Err(e) => {
                    stats.record_error(dst, port, &e);
                    return PortResult::new(port, protocol, PortState::Filtered, None);
                }
            };
            rmap_log::trace!(
                "sent {}/{} probe {src} -> {dst}:{port} try={try_no}",
                protocol.as_str(),
                self.scan_type.label()
            );
            if let Ok(Ok(reply)) = timeout(timing.connect_timeout, reply).await {
                let state = match protocol {
                    Protocol::Tcp => tcp_state(reply),
                    Protocol::Udp => udp_state(reply),
                };
                return PortResult::new(port, protocol, state, Some(sent.elapsed()));
            }
        }
        PortResult::new(port, protocol, silent, None)
    }

    /// Check whether `route.dst()` is up: ARP on a directly connected IPv4
    /// subnet, otherwise ICMP (or ICMPv6) echo raced against the TCP connect
    /// ping. IPv6 has no neighbour-discovery ping; the kernel resolves
    /// neighbours for the echo request itself.
    pub(crate) async fn ping(
        self: &Arc<Self>,
        route: Route,
        timing: &Timing,
        stats: &Arc<Stats>,
    ) -> Option<Duration> {
        if let Route::V4(src, dst) = route
            && let Some(rtt) = self.arp_ping(src, dst, timing).await
        {
            return rtt;
        }
        let mut racers = JoinSet::new();
        let (me, t) = (self.clone(), *timing);
        racers.spawn(async move { me.echo_ping(route, &t).await });
        let (s, t) = (stats.clone(), *timing);
        racers.spawn(async move { crate::tcp::ping(route.dst(), &t, &s).await });
        while let Some(done) = racers.join_next().await {
            if let Ok(Some(rtt)) = done {
                return Some(rtt);
            }
        }
        None
    }

    pub(crate) async fn echo_ping(&self, route: Route, timing: &Timing) -> Option<Duration> {
        let (src, dst) = (route.src(), route.dst());
        let limit = timing.connect_timeout.max(Duration::from_secs(1));
        for try_no in 0..=timing.retries {
            let packet = self.inner.matcher.echo_packet(route, u16::from(try_no));
            let (_registration, reply) = self.inner.pings.register(dst);
            let sent = match self.inner.send(&packet, dst).await {
                Ok(t) => t,
                Err(e) => {
                    rmap_log::debug!("echo request to {dst} failed: {e}");
                    return None;
                }
            };
            rmap_log::trace!("sent echo request {src} -> {dst} try={try_no}");
            if let Ok(Ok(())) = timeout(limit, reply).await {
                return Some(sent.elapsed());
            }
        }
        None
    }

    /// ARP ping. `None` means ARP doesn't apply (not on a local Ethernet
    /// subnet, or no packet socket); `Some(None)` means nobody answered,
    /// which on a local subnet reliably means the host is down.
    pub(crate) async fn arp_ping(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        timing: &Timing,
    ) -> Option<Option<Duration>> {
        let iface = self.interfaces.iter().find(|i| {
            !i.loopback && i.addr == src && i.addr != dst && i.index != 0 && i.on_link(dst)
        })?;
        let mac = iface.mac?;
        let fd = self.arp_socket(iface)?;
        let frame = Matcher::arp_frame(mac, src, dst);
        let limit = timing.connect_timeout.max(Duration::from_millis(500));
        for try_no in 0..=timing.retries {
            let (_registration, reply) = self.inner.pings.register(dst.into());
            self.inner.rate.wait().await;
            let sent = Instant::now();
            if let Err(e) = sys::send_frame(&fd, &frame).await {
                rmap_log::debug!("ARP request for {dst} on {} failed: {e}", iface.name);
                return None;
            }
            rmap_log::trace!("sent ARP who-has {dst} on {} try={try_no}", iface.name);
            if let Ok(Ok(())) = timeout(limit, reply).await {
                return Some(Some(sent.elapsed()));
            }
        }
        Some(None)
    }

    /// The ARP socket for an interface, opened (and its listener started)
    /// on first use.
    fn arp_socket(&self, iface: &Interface) -> Option<Arc<AsyncFd<OwnedFd>>> {
        let mut arp = self.arp.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = arp.get(&iface.index) {
            return existing.clone();
        }
        let opened = sys::arp_socket(iface.index).and_then(sys::register);
        let fd = match opened {
            Ok(fd) => {
                rmap_log::info!("ARP discovery enabled on {}", iface.name);
                Some(Arc::new(fd))
            }
            Err(e) => {
                rmap_log::warn!("ARP discovery unavailable on {}: {e}", iface.name);
                None
            }
        };
        if let Some(fd) = &fd {
            let (fd, inner) = (fd.clone(), self.inner.clone());
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    match sys::recv_packet(&fd, &mut buf).await {
                        Ok(n) => {
                            if let Some(m) = Matcher::match_arp(&buf[..n]) {
                                inner.dispatch(m);
                            }
                        }
                        Err(e) => {
                            rmap_log::trace!("ARP listener: {e}");
                            sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            });
            self.tasks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(task.abort_handle());
        }
        arp.insert(iface.index, fd.clone());
        fd
    }
}
