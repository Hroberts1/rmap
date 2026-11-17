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
//! Diagnostics go to `rmap_log`: the scan's configuration and summary at
//! `info`, per-host results at `debug`, and every probe at `trace`.
//! Unexpected connect errors are tallied by kind so odd network behaviour
//! shows up in the summary even when it isn't logged line by line.

pub mod tcp;

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmap_core::{HostState, PortList, PortState, ScanEvent, Target, Timing};
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
}

impl ScanConfig {
    /// One-line description for logs.
    pub fn describe(&self) -> String {
        let shown: Vec<String> = self
            .targets
            .iter()
            .take(10)
            .map(ToString::to_string)
            .collect();
        let more = self.targets.len().saturating_sub(shown.len());
        format!(
            "targets=[{}{}] ports={} timing=T{}({}) concurrency={} host_parallelism={} timeout={:?} retries={} discovery={}",
            shown.join(","),
            if more > 0 {
                format!(",+{more} more")
            } else {
                String::new()
            },
            self.ports.len(),
            self.timing.level,
            self.timing.name,
            self.timing.concurrency,
            self.timing.host_parallelism,
            self.timing.connect_timeout,
            self.timing.retries,
            self.discovery,
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
    probe_slots: Semaphore,
    tx: UnboundedSender<ScanEvent>,
    progress: Arc<Progress>,
    stats: Arc<Stats>,
}

impl Shared {
    fn warn_ui(&self, msg: String) {
        let _ = self.tx.send(ScanEvent::Warning(msg));
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
    let hosts: u64 = config.targets.iter().map(Target::count).sum();
    let per_host = config.ports.len();
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
        probe_slots: Semaphore::new(config.timing.concurrency),
        tx,
        progress,
        stats,
    });

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

    let (state, rtt) = if shared.discovery {
        match tcp::ping(ip, &shared.timing, &shared.stats).await {
            Some(rtt) => (HostState::Up, Some(rtt)),
            None => (HostState::Down, None),
        }
    } else {
        (HostState::Assumed, None)
    };
    let counter = if state == HostState::Down {
        &shared.stats.hosts_down
    } else {
        &shared.stats.hosts_up
    };
    counter.fetch_add(1, Ordering::Relaxed);
    rmap_log::debug!("host {ip} {state:?} rtt={rtt:?}");
    let _ = shared.tx.send(ScanEvent::Host {
        ip,
        hostname,
        state,
        rtt,
    });
    if state == HostState::Down {
        shared
            .progress
            .completed
            .fetch_add(shared.ports.len() as u64, Ordering::Relaxed);
        return;
    }

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
        probes.spawn(async move {
            let _slot = slot;
            let result = tcp::probe(ip, port, &sh.timing, &sh.stats).await;
            sh.progress.completed.fetch_add(1, Ordering::Relaxed);
            match result.state {
                PortState::Open => {
                    sh.stats.open.fetch_add(1, Ordering::Relaxed);
                    rmap_log::debug!("open {ip}:{port} rtt={:?}", result.rtt);
                    let _ = sh.tx.send(ScanEvent::Port { ip, result });
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
    rmap_log::debug!("host {ip} done in {elapsed:?}: closed={closed} filtered={filtered}");
    let _ = shared.tx.send(ScanEvent::HostDone {
        ip,
        closed,
        filtered,
        elapsed,
    });
}

#[cfg(test)]
mod tests;
