//! Raw sockets on Linux: send hand-built packets, read replies on
//! listener tasks, and hand each matched reply to the probe waiting for it.

use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::Ipv4Addr;
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

use super::matcher::{Matched, Matcher, Reply, tcp_state, udp_state};
use super::sys::{self, Interface};
use crate::Stats;
use crate::payloads::udp_payload;
use crate::rate::RateLimiter;

type PortKey = (Ipv4Addr, u16, Protocol);

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
    rate: RateLimiter,
    ports: Waiters<PortKey, Reply>,
    pings: Waiters<Ipv4Addr, ()>,
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

    async fn send(&self, packet: &[u8], dst: Ipv4Addr) -> io::Result<Instant> {
        self.rate.wait().await;
        let sent = Instant::now();
        sys::send_ipv4(&self.send, packet, dst).await?;
        Ok(sent)
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
async fn listen(
    what: &'static str,
    fd: AsyncFd<OwnedFd>,
    inner: Arc<Inner>,
    handle: fn(&Matcher, &[u8]) -> Option<Matched>,
) {
    let mut buf = vec![0u8; 65_536];
    let mut errors = 0u32;
    loop {
        match sys::recv_packet(&fd, &mut buf).await {
            Ok(n) => {
                errors = 0;
                if let Some(m) = handle(&inner.matcher, &buf[..n]) {
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
            Ok((_, std::net::SocketAddr::V4(from))) => inner.dispatch(Matched::Port {
                ip: *from.ip(),
                port: from.port(),
                protocol: Protocol::Udp,
                reply: Reply::Data,
            }),
            Ok(_) => {}
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
        let rate = RateLimiter::for_timing(timing);
        rmap_log::info!(
            "raw backend ready: scan={scan_type:?} rate={}pps udp_port={udp_port} interfaces={:?}",
            crate::rate::packet_rate(timing),
            interfaces
                .iter()
                .map(|i| format!("{}={}/{}", i.name, i.addr, i.netmask))
                .collect::<Vec<_>>()
        );
        let inner = Arc::new(Inner {
            matcher: Matcher::new(udp_port),
            send,
            rate,
            ports: Waiters::new(),
            pings: Waiters::new(),
        });
        let mut tasks = vec![
            tokio::spawn(listen("ICMP", icmp, inner.clone(), Matcher::match_icmp)).abort_handle(),
        ];
        if let Some(tcp) = tcp {
            tasks.push(
                tokio::spawn(listen("TCP", tcp, inner.clone(), Matcher::match_tcp)).abort_handle(),
            );
        }
        if let Some(udp) = udp {
            tasks.push(tokio::spawn(listen_udp(udp, inner.clone())).abort_handle());
        }
        Ok(RawScanner {
            scan_type,
            inner,
            interfaces,
            arp: Mutex::new(HashMap::new()),
            tasks: Mutex::new(tasks),
        })
    }

    /// Probe one port of `dst` from `src`. Connect scans don't come here.
    pub(crate) async fn probe(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        port: u16,
        timing: &Timing,
        stats: &Stats,
    ) -> PortResult {
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
                Protocol::Tcp => m.syn_packet(src, dst, port, try_no),
                Protocol::Udp => m.udp_packet(src, dst, port, &payload),
            };
            let (_registration, reply) = self.inner.ports.register((dst, port, protocol));
            let sent = match self.inner.send(&packet, dst).await {
                Ok(t) => t,
                Err(e) => {
                    stats.record_error(dst.into(), port, &e);
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

    /// Check whether `dst` is up: ARP on a directly connected subnet,
    /// otherwise ICMP echo raced against the TCP connect ping.
    pub(crate) async fn ping(
        self: &Arc<Self>,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        timing: &Timing,
        stats: &Arc<Stats>,
    ) -> Option<Duration> {
        if let Some(rtt) = self.arp_ping(src, dst, timing).await {
            return rtt;
        }
        let mut racers = JoinSet::new();
        let (me, t) = (self.clone(), *timing);
        racers.spawn(async move { me.echo_ping(src, dst, &t).await });
        let (s, t) = (stats.clone(), *timing);
        racers.spawn(async move { crate::tcp::ping(dst.into(), &t, &s).await });
        while let Some(done) = racers.join_next().await {
            if let Ok(Some(rtt)) = done {
                return Some(rtt);
            }
        }
        None
    }

    pub(crate) async fn echo_ping(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        timing: &Timing,
    ) -> Option<Duration> {
        let limit = timing.connect_timeout.max(Duration::from_secs(1));
        for try_no in 0..=timing.retries {
            let packet = self.inner.matcher.echo_packet(src, dst, u16::from(try_no));
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
            let (_registration, reply) = self.inner.pings.register(dst);
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
