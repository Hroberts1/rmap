//! The rmap scan engine.
//!
//! A scan runs as a tree of tokio tasks: one coordinator, one task per host
//! (bounded by `Timing::host_parallelism`), and one task per probe (bounded
//! by `Timing::concurrency`). Results stream back over a channel, and
//! progress is published through shared atomics so the UI can poll it
//! without per-probe messages.
//!
//! Stopping a scan aborts the coordinator. Each level owns its children in a
//! `JoinSet`, so dropping it cancels everything below.
//!
//! Ports are probed through a backend chosen per scan (see `backend`): raw
//! sockets for SYN and UDP scans and ICMP/ARP discovery when the platform
//! and privileges allow, otherwise ordinary sockets with a warning.
//!
//! Diagnostics go to `rmap_log`: the scan's configuration and summary at
//! `info`, per-host results at `debug`, and every probe at `trace`.
//! Unexpected connect errors are tallied by kind so odd network behaviour
//! shows up in the summary even when it isn't logged line by line.

mod backend;
pub mod exclude;
pub mod rate;
pub mod raw;
pub mod rtt;
mod service;
pub mod tcp;
pub mod udp;
mod vuln;

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmap_core::{HostState, PortList, PortState, Protocol, ScanEvent, ScanType, Target, Timing};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::{JoinError, JoinHandle, JoinSet};

/// Unexpected errors logged individually per scan; the rest are only counted.
const DETAILED_ERRORS: u64 = 20;

/// What to scan and how.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<Target>,
    pub ports: PortList,
    pub timing: Timing,
    /// Probe each host before scanning it, and skip hosts that don't answer.
    pub discovery: bool,
    /// Technique used to probe ports.
    pub scan_type: ScanType,
    /// Identify the software behind open ports.
    pub service_detection: bool,
    /// Look up each identified service's CPEs in the local CVE database.
    /// Has no effect without `service_detection`: there is nothing to
    /// look up yet.
    pub vuln_matching: bool,
    /// Addresses never to probe, in target syntax. Hostnames are resolved at
    /// scan start; if one doesn't resolve the scan stops before sending
    /// anything. Empty means no exclusions.
    pub exclude: Vec<Target>,
    /// Most probes started per second across all hosts (discovery pings,
    /// port probes and service detection each count as one). `None` means
    /// no cap beyond the timing template.
    pub max_rate: Option<u32>,
}

impl ScanConfig {
    /// One-line description for logs.
    pub fn describe(&self) -> String {
        let list = |targets: &[Target]| {
            let shown: Vec<String> = targets.iter().take(10).map(ToString::to_string).collect();
            let more = targets.len().saturating_sub(shown.len());
            if more > 0 {
                format!("{},+{more} more", shown.join(","))
            } else {
                shown.join(",")
            }
        };
        format!(
            "targets=[{}] exclude=[{}] max_rate={} ports={} scan={:?} timing=T{}({}) concurrency={} host_parallelism={} timeout={:?} retries={} discovery={} service_detection={} vuln_matching={}",
            list(&self.targets),
            list(&self.exclude),
            self.max_rate
                .map_or("unlimited".to_string(), |r| format!("{r}/s")),
            self.ports.len(),
            self.scan_type,
            self.timing.level,
            self.timing.name,
            self.timing.concurrency,
            self.timing.host_parallelism,
            self.timing.connect_timeout,
            self.timing.retries,
            self.discovery,
            self.service_detection,
            self.vuln_matching,
        )
    }
}

/// Probe counts shared between the engine and the UI.
#[derive(Debug, Default)]
pub struct Progress {
    pub total: AtomicU64,
    pub completed: AtomicU64,
}

impl Progress {
    /// Fraction complete, 0.0-1.0.
    pub fn ratio(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        (self.completed.load(Ordering::Relaxed) as f64 / total as f64).min(1.0)
    }
}

/// Counters for the end-of-scan summary.
#[derive(Debug, Default)]
pub struct Stats {
    pub open: AtomicU64,
    pub closed: AtomicU64,
    pub filtered: AtomicU64,
    pub hosts_up: AtomicU64,
    pub hosts_down: AtomicU64,
    pub unexpected_errors: AtomicU64,
    pub socket_backoffs: AtomicU64,
    pub task_panics: AtomicU64,
    error_kinds: Mutex<BTreeMap<String, u64>>,
}

impl Stats {
    /// Note a connect error that wasn't a plain refusal or timeout.
    pub fn record_error(&self, ip: IpAddr, port: u16, e: &io::Error) {
        let n = self.unexpected_errors.fetch_add(1, Ordering::Relaxed) + 1;
        let key = match e.raw_os_error() {
            Some(code) => format!("{:?}(os {code})", e.kind()),
            None => format!("{:?}", e.kind()),
        };
        *self
            .error_kinds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(key.clone())
            .or_default() += 1;
        if n <= DETAILED_ERRORS {
            rmap_log::debug!("connect {ip}:{port} failed: {e} [{key}]");
            if n == DETAILED_ERRORS {
                rmap_log::debug!("further connect errors are counted, not logged");
            }
        }
    }

    /// Error tallies as `kind=count` pairs, most frequent first.
    pub fn error_summary(&self) -> String {
        let kinds = self.error_kinds.lock().unwrap_or_else(|p| p.into_inner());
        let mut pairs: Vec<_> = kinds.iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        pairs
            .iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// A running scan.
pub struct Scan {
    pub events: UnboundedReceiver<ScanEvent>,
    pub progress: Arc<Progress>,
    pub stats: Arc<Stats>,
    task: JoinHandle<()>,
}

impl Scan {
    /// Start a scan on the given runtime. Results arrive on `events`.
    pub fn start(rt: &Handle, config: ScanConfig) -> Scan {
        rmap_log::info!("scan starting {}", config.describe());
        let (tx, events) = unbounded_channel();
        let progress = Arc::new(Progress::default());
        let stats = Arc::new(Stats::default());
        let task = rt.spawn(run(config, tx, progress.clone(), stats.clone()));
        Scan {
            events,
            progress,
            stats,
            task,
        }
    }

    /// Cancel every outstanding probe.
    pub fn stop(&self) {
        if !self.task.is_finished() {
            rmap_log::info!(
                "scan cancelled at {}/{} probes",
                self.progress.completed.load(Ordering::Relaxed),
                self.progress.total.load(Ordering::Relaxed)
            );
            self.task.abort();
        }
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl Drop for Scan {
    fn drop(&mut self) {
        self.stop();
    }
}

/// State every host task needs, shared by reference count.
struct Shared {
    ports: Box<[u16]>,
    timing: Timing,
    discovery: bool,
    scan_type: ScanType,
    prober: backend::Prober,
    /// Set once the user has been told IPv6 targets can't use raw probes.
    ipv6_warned: AtomicBool,
    probe_slots: Semaphore,
    /// The user's cap on probe starts per second, shared by every host.
    max_rate: Option<rate::RateLimiter>,
    /// Present when service detection is on.
    services: Option<service::Detection>,
    /// Present when vulnerability matching is on and there is a service
    /// detector to feed it CPEs.
    vulns: Option<vuln::Matching>,
    tx: UnboundedSender<ScanEvent>,
    progress: Arc<Progress>,
    stats: Arc<Stats>,
}

impl Shared {
    fn warn_ui(&self, msg: String) {
        let _ = self.tx.send(ScanEvent::Warning(msg));
    }

    /// Wait for a turn under the user's rate cap before starting a probe.
    async fn pace(&self) {
        if let Some(limit) = &self.max_rate {
            limit.wait().await;
        }
    }
}

/// Holds one probe slot and hands it back when dropped, even if the probe
/// task panics or is cancelled.
struct ProbeSlot(Arc<Shared>);

impl Drop for ProbeSlot {
    fn drop(&mut self) {
        self.0.probe_slots.add_permits(1);
    }
}

/// Log a child task that panicked. Cancellation is expected and ignored.
fn note_join_error(e: JoinError, what: &str, shared: &Shared) {
    if e.is_panic() {
        shared.stats.task_panics.fetch_add(1, Ordering::Relaxed);
        rmap_log::error!("{what} task panicked; its results are incomplete");
        shared.warn_ui(format!(
            "internal error while scanning {what}; see the log file"
        ));
    }
}

async fn run(
    config: ScanConfig,
    tx: UnboundedSender<ScanEvent>,
    progress: Arc<Progress>,
    stats: Arc<Stats>,
) {
    let started = Instant::now();
    let (prober, downgrade) =
        backend::Prober::select(config.scan_type, config.discovery, &config.timing);
    rmap_log::info!(
        "probing with {} for a {} scan",
        prober.describe(),
        config.scan_type.label()
    );
    if let Some(msg) = downgrade {
        rmap_log::warn!("{msg}");
        let _ = tx.send(ScanEvent::Warning(msg));
    }
    let per_host = config.ports.len();
    let exclude = match exclude::resolve(&config.exclude).await {
        Ok(list) => list,
        Err(msg) => {
            let msg = format!("{msg}; nothing was scanned");
            rmap_log::warn!("{msg}");
            let _ = tx.send(ScanEvent::Started {
                hosts: 0,
                ports_per_host: per_host,
            });
            let _ = tx.send(ScanEvent::Warning(msg));
            let _ = tx.send(ScanEvent::Finished {
                elapsed: started.elapsed(),
            });
            return;
        }
    };
    let hosts = exclude::count_hosts(&config.targets, &exclude);
    progress
        .total
        .store(hosts * per_host as u64, Ordering::Relaxed);
    let _ = tx.send(ScanEvent::Started {
        hosts,
        ports_per_host: per_host,
    });

    let host_slots = Arc::new(Semaphore::new(config.timing.host_parallelism));
    let shared = Arc::new(Shared {
        ports: config.ports.as_slice().into(),
        timing: config.timing,
        discovery: config.discovery,
        scan_type: config.scan_type,
        prober,
        ipv6_warned: AtomicBool::new(false),
        probe_slots: Semaphore::new(config.timing.concurrency),
        services: config
            .service_detection
            .then(|| service::Detection::new(config.timing)),
        vulns: (config.service_detection && config.vuln_matching).then(vuln::Matching::new),
        tx,
        progress,
        stats,
        max_rate: config.max_rate.map(rate::RateLimiter::per_second),
    });
    if hosts == 0 && !config.targets.is_empty() {
        let msg = "every target address is in the exclude list; nothing to scan".to_string();
        rmap_log::warn!("{msg}");
        shared.warn_ui(msg);
    }

    let mut host_tasks: JoinSet<IpAddr> = JoinSet::new();
    let reap = |r: Result<IpAddr, JoinError>, shared: &Shared| {
        if let Err(e) = r {
            note_join_error(e, "a host", shared);
        }
    };
    for target in config.targets {
        let addrs: Box<dyn Iterator<Item = (IpAddr, Option<String>)> + Send> = match &target {
            Target::Hostname(name) => match resolve(name).await {
                Ok(ip) => {
                    rmap_log::debug!("resolved {name} to {ip}");
                    Box::new(std::iter::once((ip, Some(name.clone()))))
                }
                Err(e) => {
                    rmap_log::warn!("could not resolve {name}: {e}");
                    shared.warn_ui(format!("could not resolve {name}: {e}"));
                    shared
                        .progress
                        .completed
                        .fetch_add(per_host as u64, Ordering::Relaxed);
                    continue;
                }
            },
            _ => Box::new(target.addrs().map(|ip| (ip, None))),
        };
        for (ip, hostname) in addrs {
            if exclude::is_excluded(&exclude, ip) {
                rmap_log::trace!("skipping excluded {ip}");
                if let Some(name) = hostname {
                    let msg = format!("skipped {name} ({ip}): it is in the exclude list");
                    rmap_log::info!("{msg}");
                    shared.warn_ui(msg);
                    shared
                        .progress
                        .completed
                        .fetch_add(per_host as u64, Ordering::Relaxed);
                }
                continue;
            }
            let slot = host_slots
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            let task_shared = shared.clone();
            host_tasks.spawn(async move {
                let _slot = slot;
                scan_host(ip, hostname, &task_shared).await;
                ip
            });
            while let Some(r) = host_tasks.try_join_next() {
                reap(r, &shared);
            }
        }
    }
    while let Some(r) = host_tasks.join_next().await {
        reap(r, &shared);
    }

    let elapsed = started.elapsed();
    let s = &shared.stats;
    let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
    rmap_log::info!(
        "scan finished in {elapsed:?}: hosts up={} down={} ports open={} closed={} filtered={} \
         probes={}/{} unexpected_errors={} socket_backoffs={} task_panics={}",
        load(&s.hosts_up),
        load(&s.hosts_down),
        load(&s.open),
        load(&s.closed),
        load(&s.filtered),
        load(&shared.progress.completed),
        load(&shared.progress.total),
        load(&s.unexpected_errors),
        load(&s.socket_backoffs),
        load(&s.task_panics),
    );
    if let Some(d) = &shared.services {
        rmap_log::info!(
            "service detection: {} of {} open ports identified",
            load(&d.identified),
            load(&d.attempted)
        );
    }
    if load(&s.unexpected_errors) > 0 {
        rmap_log::info!("connect errors by kind: {}", s.error_summary());
    }
    if load(&s.socket_backoffs) > 0 {
        shared.warn_ui(format!(
            "ran out of local sockets {} times; results are valid but the scan was slowed",
            load(&s.socket_backoffs)
        ));
    }
    let _ = shared.tx.send(ScanEvent::Finished { elapsed });
}

/// Resolve a name, preferring an IPv4 address.
async fn resolve(name: &str) -> io::Result<IpAddr> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((name, 0))
        .await?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses returned"))
}

async fn scan_host(ip: IpAddr, hostname: Option<String>, shared: &Arc<Shared>) {
    let started = Instant::now();

    #[cfg(test)]
    if ip == tests::PANIC_IP {
        panic!("test-only panic for {ip}");
    }

    let prober = shared.prober.for_host(ip, shared.scan_type);
    if ip.is_ipv6()
        && shared.scan_type.needs_raw_sockets()
        && matches!(prober, backend::HostProber::Unprivileged(_))
        && !matches!(shared.prober, backend::Prober::Unprivileged)
        && !shared.ipv6_warned.swap(true, Ordering::Relaxed)
    {
        let msg = format!(
            "raw scans support IPv4 only so far; IPv6 targets get an unprivileged {} scan",
            if shared.scan_type == ScanType::Udp {
                "UDP"
            } else {
                "TCP connect"
            }
        );
        rmap_log::warn!("{msg}");
        shared.warn_ui(msg);
    }

    let (state, rtt, mac) = if shared.discovery {
        shared.pace().await;
        match prober.ping(ip, &shared.timing, &shared.stats).await {
            Some((rtt, mac)) => (HostState::Up, Some(rtt), mac),
            None => (HostState::Down, None, None),
        }
    } else {
        (HostState::Assumed, None, None)
    };
    let counter = if state == HostState::Down {
        &shared.stats.hosts_down
    } else {
        &shared.stats.hosts_up
    };
    counter.fetch_add(1, Ordering::Relaxed);
    rmap_log::debug!("host {ip} {state:?} rtt={rtt:?} mac={mac:?}");
    let _ = shared.tx.send(ScanEvent::Host {
        ip,
        hostname,
        state,
        rtt,
    });
    if let Some(mac) = mac {
        let _ = shared.tx.send(ScanEvent::Mac { ip, mac });
    }
    if state == HostState::Down {
        shared
            .progress
            .completed
            .fetch_add(shared.ports.len() as u64, Ordering::Relaxed);
        return;
    }

    let host_rtt = Arc::new(rtt::HostRtt::seeded(rtt));
    rmap_log::debug!(
        "host {ip} probe timeout starts at {:?}",
        host_rtt.timeout(&shared.timing, 0)
    );
    let closed = Arc::new(AtomicU32::new(0));
    let filtered = Arc::new(AtomicU32::new(0));
    let mut probes = JoinSet::new();
    for &port in &shared.ports {
        // Wait for a free probe slot before spawning, so memory stays flat
        // no matter how many ports are queued.
        shared
            .probe_slots
            .acquire()
            .await
            .expect("semaphore never closed")
            .forget();
        let slot = ProbeSlot(shared.clone());
        let (sh, closed, filtered) = (shared.clone(), closed.clone(), filtered.clone());
        let (prober, host_rtt) = (prober.clone(), host_rtt.clone());
        probes.spawn(async move {
            sh.pace().await;
            let result = prober
                .probe(ip, port, &sh.timing, &sh.stats, &host_rtt)
                .await;
            sh.progress.completed.fetch_add(1, Ordering::Relaxed);
            match result.state {
                PortState::Open | PortState::OpenFiltered => {
                    sh.stats.open.fetch_add(1, Ordering::Relaxed);
                    rmap_log::debug!(
                        "{} {ip}:{port}/{} rtt={:?}",
                        result.state.as_str(),
                        result.protocol.as_str(),
                        result.rtt
                    );
                    let open = result.state == PortState::Open;
                    let protocol = result.protocol;
                    // Free the probe slot before detection so it (and any
                    // vuln lookup after it) can't hold up the port scan.
                    let service = match sh.services.as_ref() {
                        // A UDP reply can upgrade open|filtered to open, so
                        // detection runs first and sends the Port event.
                        Some(services) if protocol == Protocol::Udp => {
                            drop(slot);
                            sh.pace().await;
                            services.identify_udp(ip, result, &sh.tx).await
                        }
                        Some(services) if open => {
                            let _ = sh.tx.send(ScanEvent::Port { ip, result });
                            drop(slot);
                            sh.pace().await;
                            services.identify(ip, port, protocol, &sh.tx).await
                        }
                        _ => {
                            let _ = sh.tx.send(ScanEvent::Port { ip, result });
                            None
                        }
                    };
                    if let Some(service) = service
                        && let Some(vulns) = sh.vulns.as_ref()
                    {
                        vulns.check(ip, protocol, port, &service.cpes, &sh.tx);
                    }
                }
                PortState::Closed => {
                    sh.stats.closed.fetch_add(1, Ordering::Relaxed);
                    closed.fetch_add(1, Ordering::Relaxed);
                }
                PortState::Filtered => {
                    sh.stats.filtered.fetch_add(1, Ordering::Relaxed);
                    filtered.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        while let Some(r) = probes.try_join_next() {
            if let Err(e) = r {
                note_join_error(e, &format!("{ip}"), shared);
            }
        }
    }
    while let Some(r) = probes.join_next().await {
        if let Err(e) = r {
            note_join_error(e, &format!("{ip}"), shared);
        }
    }

    let (closed, filtered) = (
        closed.load(Ordering::Relaxed),
        filtered.load(Ordering::Relaxed),
    );
    let elapsed = started.elapsed();
    let est = host_rtt.snapshot();
    rmap_log::debug!(
        "host {ip} done in {elapsed:?}: closed={closed} filtered={filtered} srtt={:?} timeout={:?}",
        est.srtt(),
        est.timeout(&shared.timing, 0)
    );
    let _ = shared.tx.send(ScanEvent::HostDone {
        ip,
        closed,
        filtered,
        elapsed,
    });
}

#[cfg(test)]
mod tests;
