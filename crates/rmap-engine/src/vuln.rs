//! Vulnerability matching hook (Milestone 4).
//!
//! The engine opens the local CVE database once per scan with
//! [`Matching::open`], then calls [`Matching::check`] right after service
//! detection identifies a service on an open port, with that service's
//! CPEs. Each check is an indexed lookup in a local SQLite file - quick
//! enough that there is no separate concurrency limit the way detection
//! has one for its network probes.

use std::net::IpAddr;
use std::path::PathBuf;

use rmap_core::{Protocol, ScanEvent, Vulnerability};
use rmap_vuln::{Database, DbError};
use tokio::sync::mpsc::UnboundedSender;

pub(crate) struct Matching {
    db: Database,
}

impl Matching {
    /// Opens `path`, or [`rmap_vuln::default_path`] when `None`. The error
    /// is a message for the user saying why matching is skipped.
    pub fn open(path: Option<PathBuf>) -> Result<Matching, String> {
        let path = path
            .or_else(rmap_vuln::default_path)
            .ok_or("no data directory for the vulnerability database; CVE matching skipped")?;
        let db = Database::open(&path).map_err(|e| match e {
            DbError::NotFound => format!(
                "no vulnerability data at {}; CVE matching skipped",
                path.display()
            ),
            e => format!("{}: {e}; CVE matching skipped", path.display()),
        })?;
        let info = db.info();
        rmap_log::info!(
            "vulnerability database {}: {} CVEs, built {}, source {}",
            path.display(),
            info.cve_count,
            info.built_at,
            info.source
        );
        Ok(Matching { db })
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
            for finding in self.db.find(cpe) {
                if !findings.iter().any(|f| f.id == finding.id) {
                    findings.push(finding);
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
