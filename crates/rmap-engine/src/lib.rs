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

mod tcp;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use rmap_core::{HostState, PortList, PortState, ScanEvent, Target, Timing};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::{JoinHandle, JoinSet};

/// What to scan and how.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<Target>,
    pub ports: PortList,
    pub timing: Timing,
    /// Probe each host before scanning it, and skip hosts that don't answer.
    pub discovery: bool,
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

/// A running scan.
pub struct Scan {
    pub events: UnboundedReceiver<ScanEvent>,
    pub progress: Arc<Progress>,
    task: JoinHandle<()>,
}

impl Scan {
    /// Start a scan on the given runtime. Results arrive on `events`.
    pub fn start(rt: &Handle, config: ScanConfig) -> Scan {
        let (tx, events) = unbounded_channel();
        let progress = Arc::new(Progress::default());
        let task = rt.spawn(run(config, tx, progress.clone()));
        Scan {
            events,
            progress,
            task,
        }
    }

    /// Cancel every outstanding probe.
    pub fn stop(&self) {
        self.task.abort();
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl Drop for Scan {
    fn drop(&mut self) {
        self.task.abort();
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
}

async fn run(config: ScanConfig, tx: UnboundedSender<ScanEvent>, progress: Arc<Progress>) {
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
    });

    let mut host_tasks = JoinSet::new();
    for target in config.targets {
        let addrs: Box<dyn Iterator<Item = (IpAddr, Option<String>)> + Send> = match &target {
            Target::Hostname(name) => match resolve(name).await {
                Some(ip) => Box::new(std::iter::once((ip, Some(name.clone())))),
                None => {
                    let _ = shared
                        .tx
                        .send(ScanEvent::Warning(format!("could not resolve {name}")));
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
            let shared = shared.clone();
            host_tasks.spawn(async move {
                scan_host(ip, hostname, &shared).await;
                drop(slot);
            });
            while host_tasks.try_join_next().is_some() {}
        }
    }
    while host_tasks.join_next().await.is_some() {}

    let _ = shared.tx.send(ScanEvent::Finished {
        elapsed: started.elapsed(),
    });
}

/// Resolve a name, preferring an IPv4 address.
async fn resolve(name: &str) -> Option<IpAddr> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((name, 0))
        .await
        .ok()?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
}

async fn scan_host(ip: IpAddr, hostname: Option<String>, shared: &Arc<Shared>) {
    let started = Instant::now();
    let (state, rtt) = if shared.discovery {
        match tcp::ping(ip, &shared.timing).await {
            Some(rtt) => (HostState::Up, Some(rtt)),
            None => (HostState::Down, None),
        }
    } else {
        (HostState::Assumed, None)
    };
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
        let slot = shared
            .probe_slots
            .acquire()
            .await
            .expect("semaphore never closed");
        slot.forget();
        let (shared, closed, filtered) = (shared.clone(), closed.clone(), filtered.clone());
        probes.spawn(async move {
            let result = tcp::probe(ip, port, &shared.timing).await;
            shared.probe_slots.add_permits(1);
            shared.progress.completed.fetch_add(1, Ordering::Relaxed);
            match result.state {
                PortState::Open => {
                    let _ = shared.tx.send(ScanEvent::Port { ip, result });
                }
                PortState::Closed => {
                    closed.fetch_add(1, Ordering::Relaxed);
                }
                PortState::Filtered => {
                    filtered.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        while probes.try_join_next().is_some() {}
    }
    while probes.join_next().await.is_some() {}

    let _ = shared.tx.send(ScanEvent::HostDone {
        ip,
        closed: closed.load(Ordering::Relaxed),
        filtered: filtered.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmap_core::parse_targets;
    use tokio::net::TcpListener;

    #[tokio::test(flavor = "multi_thread")]
    async fn finds_an_open_port_on_localhost() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let config = ScanConfig {
            targets: parse_targets("127.0.0.1").unwrap(),
            ports: PortList::parse(&port.to_string()).unwrap(),
            timing: Timing::template(4),
            discovery: false,
        };
        let mut scan = Scan::start(&Handle::current(), config);
        let mut open = Vec::new();
        while let Some(ev) = scan.events.recv().await {
            match ev {
                ScanEvent::Port { result, .. } => open.push(result.port),
                ScanEvent::Finished { .. } => break,
                _ => {}
            }
        }
        assert_eq!(open, [port]);
        assert_eq!(scan.progress.ratio(), 1.0);
    }
}
