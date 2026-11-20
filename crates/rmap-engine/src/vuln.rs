//! Vulnerability matching hook (Milestone 4).
//!
//! The engine opens the local CVE database once per scan with
//! [`Matching::start`], then calls [`Matching::check`] right after service
//! detection identifies a service on an open port. Each check is an
//! indexed lookup in a local SQLite file - quick enough that there is no
//! separate concurrency limit the way detection has one for its network
//! probes.
//!
//! Every checked port also gets a [`VulnCheck`] status, so a port that
//! couldn't be checked says so instead of looking clean.

use std::net::IpAddr;
use std::path::PathBuf;

use rmap_core::{Protocol, ScanEvent, Service, VulnCheck, VulnData, Vulnerability};
use rmap_vuln::{Database, DbError};
use tokio::sync::mpsc::UnboundedSender;

pub(crate) struct Matching {
    /// `None` when matching was asked for but no usable database opened;
    /// every port then gets [`VulnCheck::NoDatabase`].
    db: Option<Database>,
}

impl Matching {
    /// Opens `path`, or [`rmap_vuln::default_path`] when `None`. Sends
    /// `VulnData` if it opened, else one warning saying why matching is
    /// skipped.
    pub fn start(path: Option<PathBuf>, tx: &UnboundedSender<ScanEvent>) -> Matching {
        match open(path) {
            Ok(db) => {
                let info = db.info();
                let _ = tx.send(ScanEvent::VulnData(VulnData {
                    built_at: info.built_at.clone(),
                    cve_count: info.cve_count,
                    source: info.source.clone(),
                }));
                Matching { db: Some(db) }
            }
            Err(msg) => {
                rmap_log::info!("{msg}");
                let _ = tx.send(ScanEvent::Warning(msg));
                Matching { db: None }
            }
        }
    }

    /// Looks up the CPEs a detected service carries and reports any
    /// matches, then the port's status. `Vulnerabilities` is skipped when
    /// there are none, so a clean service doesn't flood the UI with empty
    /// events.
    pub fn check(
        &self,
        ip: IpAddr,
        protocol: Protocol,
        port: u16,
        service: &Service,
        tx: &UnboundedSender<ScanEvent>,
    ) {
        let status = match &self.db {
            None => VulnCheck::NoDatabase,
            Some(db) => {
                let (findings, status) = lookup(db, service);
                if !findings.is_empty() {
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
                status
            }
        };
        rmap_log::debug!("vuln check {ip}:{port}/{}: {status}", protocol.as_str());
        let _ = tx.send(ScanEvent::VulnCheck {
            ip,
            protocol,
            port,
            status,
        });
    }
}

fn open(path: Option<PathBuf>) -> Result<Database, String> {
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
    Ok(db)
}

/// Matches every checkable CPE the service carries, deduplicated by CVE id
/// (more than one CPE, or more than one match rule, can name the same
/// CVE), and one status for the port: `Checked` (`CheckedUpstreamOnly` for
/// a distro build) if any CPE could be looked up, else `VersionHidden`,
/// else `NotCovered`.
///
/// A CPE with no version is not looked up at all: its `*` would fall
/// inside every "before version X" range and match CVEs it can't be shown
/// to have.
fn lookup(db: &Database, service: &Service) -> (Vec<Vulnerability>, VulnCheck) {
    // Prefer detection's human-readable names over the CPE's.
    let product = |cpe_product: &str| {
        service
            .product
            .clone()
            .unwrap_or_else(|| cpe_product.to_string())
    };
    let unset = |field: &str| matches!(field, "" | "*" | "-");
    let mut findings: Vec<Vulnerability> = Vec::new();
    let mut best: Option<(u8, VulnCheck)> = None;
    for cpe in &service.cpes {
        // cpe : 2.3 : part : vendor : product : version : update : ...
        let f: Vec<&str> = cpe.split(':').collect();
        let (Some(vendor), Some(name), Some(version)) = (f.get(3), f.get(4), f.get(5)) else {
            continue;
        };
        let candidate = if !db.knows_product(vendor, name) {
            (
                1,
                VulnCheck::NotCovered {
                    product: product(name),
                },
            )
        } else if unset(version) {
            (
                2,
                VulnCheck::VersionHidden {
                    product: product(name),
                },
            )
        } else {
            for finding in db.find(cpe) {
                if !findings.iter().any(|f| f.id == finding.id) {
                    findings.push(finding);
                }
            }
            let version = match (&service.version, f.get(6)) {
                (Some(v), _) => v.clone(),
                (None, Some(update)) if !unset(update) => format!("{version}{update}"),
                (None, _) => version.to_string(),
            };
            (
                3,
                VulnCheck::Checked {
                    product: product(name),
                    version,
                    matches: 0,
                },
            )
        };
        if best.as_ref().is_none_or(|(rank, _)| candidate.0 > *rank) {
            best = Some(candidate);
        }
    }
    let mut status = match (best, &service.product) {
        (
            Some((
                _,
                VulnCheck::Checked {
                    product, version, ..
                },
            )),
            _,
        ) if let Some(d) = distro(service) => VulnCheck::CheckedUpstreamOnly {
            product,
            version,
            matches: 0,
            distro: d.to_string(),
        },
        (Some((_, status)), _) => status,
        // A named product rmap has no CPE for: no data to check it with.
        (None, Some(p)) => VulnCheck::NotCovered { product: p.clone() },
        (None, None) => VulnCheck::NoProduct,
    };
    if let VulnCheck::Checked { matches, .. } | VulnCheck::CheckedUpstreamOnly { matches, .. } =
        &mut status
    {
        // Conditional and client-only matches are reported but not counted.
        let counted = findings
            .iter()
            .filter(|f| f.condition.is_none() && !f.client_only)
            .count();
        *matches = u32::try_from(counted).unwrap_or(u32::MAX);
    }
    (findings, status)
}

/// The distro a package tag in the version or banner info names
/// (`Ubuntu-2ubuntu3.5`, `Debian-2+deb12u3`, `9.9p1-11.0.1.el10`,
/// `FreeBSD-20240806`): its build may carry fixes the upstream version
/// number doesn't show.
fn distro(service: &Service) -> Option<&'static str> {
    let el_tag = |t: &str| {
        t.match_indices(".el")
            .any(|(i, _)| t[i + 3..].starts_with(|c: char| c.is_ascii_digit()))
    };
    [&service.version, &service.info]
        .into_iter()
        .flatten()
        .find_map(|t| {
            if t.contains("Ubuntu-") {
                Some("Ubuntu")
            } else if t.contains("Debian-") || t.contains("+deb") {
                Some("Debian")
            } else if t.contains("FreeBSD-") {
                Some("FreeBSD")
            } else if el_tag(t) {
                Some("Enterprise Linux")
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distro_package_tags() {
        let svc = |version: &str, info: &str| Service {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: Some(version.into()),
            info: Some(info.into()),
            ..Service::default()
        };
        let cases = [
            ("10.2p1", "protocol 2.0; Ubuntu-2ubuntu3.5", Some("Ubuntu")),
            ("9.2p1", "protocol 2.0; Debian-2+deb12u3", Some("Debian")),
            ("9.9p1-11.0.1.el10", "", Some("Enterprise Linux")),
            ("9.7", "FreeBSD-20240806", Some("FreeBSD")),
            ("9.9", "protocol 2.0", None),
            ("9.9", "help.else", None),
        ];
        for (version, info, want) in cases {
            assert_eq!(distro(&svc(version, info)), want, "{version} {info}");
        }
    }
}
