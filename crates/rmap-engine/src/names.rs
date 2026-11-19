//! Hook from the scan engine into `rmap-names`: look up each live host's
//! names while its ports are scanned, and report them as one
//! `ScanEvent::Hostnames`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rmap_core::{ScanEvent, Timing};
use tokio::task::JoinSet;

use crate::Shared;

/// Name lookup settings for one scan.
#[derive(Debug, Clone)]
pub(crate) struct Naming {
    /// Where reverse DNS queries go; `None` skips reverse DNS.
    pub dns: Option<SocketAddr>,
    /// How long each lookup waits for its reply.
    pub wait: Duration,
}

impl Naming {
    /// Settings for a scan, using `dns_server` if the user set one and the
    /// system's resolver otherwise.
    pub fn new(dns_server: Option<IpAddr>, timing: &Timing) -> Self {
        let dns = match dns_server {
            Some(ip) => {
                rmap_log::debug!("reverse DNS server {ip} from the setup form");
                Some(SocketAddr::new(ip, rmap_names::DNS_PORT))
            }
            None => {
                let dns = rmap_names::system_dns_server();
                rmap_log::debug!("reverse DNS server {dns:?} from the system");
                dns
            }
        };
        Naming {
            dns,
            wait: timing
                .connect_timeout
                .clamp(Duration::from_millis(500), Duration::from_secs(2)),
        }
    }

    /// One line for the scan log.
    pub fn describe(&self) -> String {
        match self.dns {
            Some(dns) => format!(
                "names: reverse DNS via {dns}, NetBIOS, mDNS, wait {:?}",
                self.wait
            ),
            None => format!(
                "names: NetBIOS, mDNS (no DNS server for reverse DNS), wait {:?}",
                self.wait
            ),
        }
    }
}

/// A spawned lookup that is cancelled when dropped, so stopping a scan
/// (which drops the host's task) stops its name lookups too.
pub(crate) struct LookupTask(pub tokio::task::JoinHandle<()>);

impl Drop for LookupTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl LookupTask {
    pub fn spawn(ip: IpAddr, naming: Naming, shared: Arc<Shared>) -> Self {
        LookupTask(tokio::spawn(lookup(ip, naming, shared)))
    }

    /// Wait for the lookup to finish.
    pub async fn finish(mut self) -> Result<(), tokio::task::JoinError> {
        (&mut self.0).await
    }
}

/// Look up `ip`'s names from every source at once and send what was found.
/// Each query waits its turn under the rate cap like any other probe.
async fn lookup(ip: IpAddr, naming: Naming, shared: Arc<Shared>) {
    let wait = naming.wait;
    let mut queries = JoinSet::new();
    // Loopback always reverses to "localhost"; don't ask a DNS server.
    if let Some(server) = naming.dns.filter(|_| !ip.is_loopback()) {
        let sh = shared.clone();
        queries.spawn(async move {
            sh.pace().await;
            rmap_names::reverse_dns(ip, server, wait).await
        });
    }
    let sh = shared.clone();
    queries.spawn(async move {
        sh.pace().await;
        rmap_names::netbios(ip, wait).await
    });
    let sh = shared.clone();
    queries.spawn(async move {
        sh.pace().await;
        rmap_names::mdns(ip, wait).await
    });
    let mut found = Vec::new();
    while let Some(done) = queries.join_next().await {
        match done {
            Ok(name) => found.extend(name),
            Err(e) => crate::note_join_error(e, &format!("{ip} name lookup"), &shared),
        }
    }
    let names = rmap_names::rank(found);
    rmap_log::debug!("host {ip} names: {names:?}");
    if !names.is_empty() {
        let _ = shared.tx.send(ScanEvent::Hostnames { ip, names });
    }
}
