//! Vulnerability matching hook (Milestone 4).
//!
//! The engine calls [`Matching::check`] right after service detection
//! identifies a service on an open port, with that service's CPEs. It is
//! a plain local lookup against the database already loaded in memory -
//! no I/O, so there is no separate concurrency limit the way detection
//! has one for its network probes.

use std::net::IpAddr;

use rmap_core::{Protocol, ScanEvent, Vulnerability};
use rmap_vuln::Database;
use tokio::sync::mpsc::UnboundedSender;

pub(crate) struct Matching {
    db: Database,
}

impl Matching {
    pub fn new() -> Matching {
        Matching {
            db: Database::builtin(),
        }
    }

    /// Looks up every CPE a detected service carries and reports any
    /// matches, deduplicated by CVE id (more than one CPE, or more than
    /// one match rule, can name the same CVE). Sends nothing when there
    /// are none, so a clean service doesn't flood the UI with empty events.
    pub fn check(
        &self,
        ip: IpAddr,
        protocol: Protocol,
        port: u16,
        cpes: &[String],
        tx: &UnboundedSender<ScanEvent>,
    ) {
        let mut findings: Vec<Vulnerability> = Vec::new();
        for cpe in cpes {
            for entry in self.db.find(cpe) {
                if !findings.iter().any(|f| f.id == entry.finding.id) {
                    findings.push(entry.finding.clone());
                }
            }
        }
        if findings.is_empty() {
            return;
        }
        rmap_log::debug!(
            "{} potential {} for {ip}:{port}/{}: {}",
            findings.len(),
            if findings.len() == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
            protocol.as_str(),
            findings
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = tx.send(ScanEvent::Vulnerabilities {
            ip,
            protocol,
            port,
            findings,
        });
    }
}
